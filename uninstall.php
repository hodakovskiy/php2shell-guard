<?php
/**
 * Removes everything the plugin stored. Runs only when the plugin is deleted.
 */
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

foreach ( array(
	'p2s_settings',
	'p2s_results',
	'p2s_ack',
	'p2s_notified',
	'p2s_events',
	'p2s_alert_log',
	'p2s_baseline',
	'p2s_seen',
) as $option ) {
	delete_option( $option );
}

foreach ( array( 'p2s_scan', 'p2s_watch', 'p2s_heartbeat' ) as $hook ) {
	wp_clear_scheduled_hook( $hook );
}

delete_transient( 'p2s_lock' );
delete_transient( 'p2s_pstate' );
delete_transient( 'p2s_rt' );

global $wpdb;
// phpcs:ignore WordPress.DB.DirectDatabaseQuery
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_p2s\_%' OR option_name LIKE '\_transient\_timeout\_p2s\_%'" );
