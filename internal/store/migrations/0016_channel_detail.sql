-- 0016_channel_detail: why a channel failed or was ended by the gateway. close_detail is a classified, address-free
-- description (never raw error text); gateway_exit_code is the 80-90 code sent to the agent.

-- +goose Up
ALTER TABLE ssh_channels ADD COLUMN close_detail TEXT;
ALTER TABLE ssh_channels ADD COLUMN gateway_exit_code INTEGER;
CREATE INDEX ix_chan_closed ON ssh_channels (closed_at) WHERE closed_at IS NOT NULL;

-- +goose Down
SELECT 'forward-only migrations: restore the pre-migration snapshot instead';
