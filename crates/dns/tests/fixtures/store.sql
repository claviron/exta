-- Minimal store fixture; schema migrations and serial trigger policy live in Roma.
CREATE TABLE dns_zones (
    id INTEGER PRIMARY KEY, domain TEXT NOT NULL UNIQUE,
    soa_serial INTEGER NOT NULL DEFAULT 1,
    soa_refresh INTEGER NOT NULL, soa_retry INTEGER NOT NULL,
    soa_expire INTEGER NOT NULL, soa_minimum INTEGER NOT NULL,
    soa_mname TEXT NOT NULL, soa_rname TEXT NOT NULL,
    enabled INTEGER NOT NULL, updated_at TEXT
);
CREATE TABLE dns_records (
    id INTEGER PRIMARY KEY,
    zone_id INTEGER NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
    name TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL,
    ttl INTEGER NOT NULL, priority INTEGER, weight INTEGER, port INTEGER,
    enabled INTEGER NOT NULL, updated_at TEXT,
    UNIQUE(zone_id, name, type, value)
);
CREATE TRIGGER fixture_zone_serial AFTER UPDATE ON dns_zones
WHEN NEW.soa_serial = OLD.soa_serial AND NEW.enabled != OLD.enabled
BEGIN UPDATE dns_zones SET soa_serial=soa_serial+1 WHERE id=NEW.id; END;
CREATE TRIGGER fixture_record_insert AFTER INSERT ON dns_records
BEGIN UPDATE dns_zones SET soa_serial=soa_serial+1 WHERE id=NEW.zone_id; END;
CREATE TRIGGER fixture_record_update AFTER UPDATE ON dns_records
BEGIN UPDATE dns_zones SET soa_serial=soa_serial+1 WHERE id=NEW.zone_id; END;
CREATE TRIGGER fixture_record_delete AFTER DELETE ON dns_records
BEGIN UPDATE dns_zones SET soa_serial=soa_serial+1 WHERE id=OLD.zone_id; END;
-- Fail at COMMIT after every mutation statement succeeded.
CREATE TABLE fixture_commit_guard (
    zone_id INTEGER REFERENCES dns_zones(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TRIGGER fixture_commit_failure AFTER INSERT ON dns_records
WHEN NEW.name='deferred'
BEGIN INSERT INTO fixture_commit_guard VALUES(999); END;
