-- elasticsearch indexing pipeline schema
-- core schema for postgres triples records -> elasticsearch docs
-- functionality here enables inserts into triples (or really into
-- identity_relations) to touched subjects into the subjects_changed
-- table which acts as a work queue that can be drained by workers
-- to build updated elasticsearch documents for those records

CREATE TYPE subjects_changed_status AS ENUM ('pending',
                                             'processing',
                                             'done',
                                             'failed');

CREATE TABLE subjects_changed(
       subject uri PRIMARY KEY,
       record_combined_identity bytea,
       requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
       requested_by text,
       status subjects_changed_status NOT NULL DEFAULT 'pending',
       processing_since TIMESTAMP WITH TIME ZONE,
       indexed_at TIMESTAMP WITH TIME ZONE,
       error text,
       requeue_seq bigint NOT NULL DEFAULT 0
);

-- avoid full table scans during every poll for pending work
CREATE INDEX subjects_changed_claim_index ON subjects_changed (status, requested_at);

-- es_queue_subject must be called by all processes that add or change
-- interlex records for a subject, it defines the common process that
-- ensures that subjects get indexed or reindex into elasticsearch
-- it is also responsible for initiating NOTIFY for listeners so that
-- reingest can start before the standard polling interval, that reads
-- subjects_changed directly, polling is still retained as a backstop
-- in case something goes wrong with the notification process
CREATE OR REPLACE FUNCTION es_queue_subject(subj uri, rci bytea, requester text) RETURNS VOID AS
$$
BEGIN
    IF subj IS NOT NULL THEN
        IF NOT EXISTS (SELECT 1 FROM subjects_changed
                       WHERE status = 'pending') THEN
            -- pg_notify only fires when a transaction commits
            PERFORM pg_notify('interlex_es_queue', subj::text);
        END IF;
        INSERT INTO subjects_changed (subject, record_combined_identity, requested_by)
        VALUES (subj, rci, requester)
        ON CONFLICT (subject) DO UPDATE
        SET status = 'pending',
            record_combined_identity = COALESCE(EXCLUDED.record_combined_identity,
                                                subjects_changed.record_combined_identity),
            requested_at = now(),
            requested_by = EXCLUDED.requested_by,
            processing_since = NULL,
            indexed_at = NULL,
            error = NULL,
            -- the requeue_seq bump here makes it possible the ingest process
            -- to quickly determine whether the subject has changed again after
            -- the ingest process started
            requeue_seq = subjects_changed.requeue_seq + 1;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- subjects_changed is a purely operational table so purge_finished_subjects
-- is used to keep its size reasonable, currently called by python code, but
-- in principle could be hooked into some of the other triggers so that the
-- db can maintain homeostasis by itself
CREATE OR REPLACE FUNCTION purge_finished_subjects(
        days double precision,
        subjects uri[] DEFAULT NULL,
        dry_run boolean DEFAULT false)
RETURNS bigint AS
$$
DECLARE
    n bigint;
BEGIN
    IF dry_run THEN
        SELECT count(*) INTO n FROM subjects_changed
        WHERE status IN ('done', 'failed')
          AND COALESCE(indexed_at, requested_at)
              < now() - days * interval '1 day'
          AND (subjects IS NULL OR subject = ANY(subjects));
        RETURN n;
    END IF;
    DELETE FROM subjects_changed
    WHERE status IN ('done', 'failed')
      AND COALESCE(indexed_at, requested_at)
          < now() - days * interval '1 day'
      AND (subjects IS NULL OR subject = ANY(subjects));
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$$ LANGUAGE plpgsql;

-- queue changes to subjects that produce a new record combined identity
-- at the moment this results in reindexing all subject triples, however
-- in the future this could be used to ingest individual variants if we
-- start keying the es index on record combined identity instead of subject
CREATE OR REPLACE FUNCTION es_queue_rci_subject() RETURNS trigger AS
$$
DECLARE
    subj uri;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM identities i
                   WHERE i.identity = NEW.s
                     AND i.type = 'record_combined') THEN
        RETURN NEW;
    END IF;
    subj := namedEmbeddedSubject(NEW.o);
    PERFORM es_queue_subject(subj, NEW.s, 'rci-trigger');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- this trigger is responsible for essentially all indexing requests
-- XXX if there are perf issues during initial loading and sync of the
-- database consider disabling this trigger and running batch indexing
-- and then reenabling this trigger e.g. via
-- DROP TRIGGER IF EXISTS es_queue_rci_subject on identity_relations;
CREATE OR REPLACE TRIGGER es_queue_rci_subject
AFTER INSERT ON identity_relations
FOR EACH ROW
WHEN (NEW.p = 'hasNamedRecord')
EXECUTE FUNCTION es_queue_rci_subject();
