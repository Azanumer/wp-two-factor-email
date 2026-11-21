<?php
/**
 * Uninstall WP Two-Factor Email.
 * Removes the plugin option and all per-user 2FA data (opt-in flag and
 * any outstanding code state). No tables are created.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'w2fe_settings' );

global $wpdb;
$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key IN ( 'w2fe_enabled', 'w2fe_code_hash', 'w2fe_code_expires', 'w2fe_code_attempts' )" );
