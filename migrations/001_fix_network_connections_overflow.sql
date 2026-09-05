-- Fix integer overflow in network_connections table
-- bytes_sent and bytes_recv can exceed 2^31 (INTEGER max)
-- for long-lived connections (e.g. Firefox cumulative totals)

ALTER TABLE network_connections ALTER COLUMN bytes_recv TYPE BIGINT;
ALTER TABLE network_connections ALTER COLUMN bytes_sent TYPE BIGINT;
