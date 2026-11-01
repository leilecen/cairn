CREATE TABLE hunt_sessions(id INTEGER PRIMARY KEY,target_name TEXT,status TEXT);
CREATE TABLE attack_threads(id INTEGER PRIMARY KEY,hunt_session_id INTEGER,evaluation_status TEXT);
CREATE TABLE experiments(id INTEGER PRIMARY KEY,hunt_session_id INTEGER,attack_thread_id INTEGER,status TEXT,outcome TEXT,unknown_items_before_json TEXT,unknown_items_after_json TEXT);
INSERT INTO hunt_sessions VALUES(1,'demo','active');
INSERT INTO attack_threads VALUES(1,1,'inconclusive');
INSERT INTO experiments VALUES(1,1,1,'observed','inconclusive','["endpoint:a"]','["endpoint:a"]');
INSERT INTO experiments VALUES(2,1,1,'observed','inconclusive','["endpoint:a"]','["endpoint:a"]');
INSERT INTO experiments VALUES(3,1,1,'observed','inconclusive','["endpoint:a"]','["endpoint:a"]');
