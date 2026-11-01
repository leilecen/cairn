-- 038 inspiration asset link: 灵感按资产归类(显式 --asset 指定,或从 blocked_on 追溯兜底)
ALTER TABLE inspirations ADD COLUMN asset_id INTEGER REFERENCES target_assets(id);
CREATE INDEX IF NOT EXISTS idx_inspirations_asset ON inspirations(asset_id);
