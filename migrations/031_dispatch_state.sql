-- Explicit lifecycle for legacy backlog items that remain in the blackboard but
-- must not be claimed until the main session reactivates them.
ALTER TABLE work_items ADD COLUMN dispatch_state TEXT DEFAULT 'active';
CREATE INDEX IF NOT EXISTS idx_work_items_dispatch_state
    ON work_items(target_name, dispatch_state, status, lane, priority DESC);
