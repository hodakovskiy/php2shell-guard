<?php
/**
 * Plugin Name:       PHP2Shell Guard
 * Plugin URI:        https://github.com/hodakovskiy/php2shell-guard
 * Description:       Finds signs of a PHP2Shell compromise and warns you immediately by email, webhook (Slack/Discord/generic) or Telegram. Read-only: it never modifies or deletes your files.
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Sergey Hodakovskiy
 * Author URI:        linkedin.com/in/sergey-hodakovskiy-41b3b6288
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       php2shell-guard
 * Domain Path:       /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * ---------------------------------------------------------------------
 *  EDIT ME: your contact details.
 *  They are shown on the plugin's admin page (when problems are found),
 *  and in the footer of alert emails. Leave a value empty to hide it.
 *  You can also define these constants in wp-config.php instead.
 * ---------------------------------------------------------------------
 */
/* ---------------------------------------------------------------------
 * Контакты автора. Показываются на странице плагина при обнаружении
 * проблем и в подписи к алертам (email / Telegram).
 * --------------------------------------------------------------------- */
if ( ! defined( 'P2S_CONTACT_NAME' ) ) {
    define( 'P2S_CONTACT_NAME', 'Sergey' );
}
if ( ! defined( 'P2S_CONTACT_EMAIL' ) ) {
    define( 'P2S_CONTACT_EMAIL', 'hodakovskiy@gmail.com' );
}
if ( ! defined( 'P2S_CONTACT_TELEGRAM' ) ) {
    define( 'P2S_CONTACT_TELEGRAM', 'hodakovskiy' ); // без @
}
if ( ! defined( 'P2S_CONTACT_URL' ) ) {
    define( 'P2S_CONTACT_URL', '' ); // пусто — ссылка не показывается
}

define( 'P2S_VERSION', '1.0.0' );
define( 'P2S_FILE', __FILE__ );
define( 'P2S_DIR', plugin_dir_path( __FILE__ ) );
define( 'P2S_URL', plugin_dir_url( __FILE__ ) );

require_once P2S_DIR . 'includes/class-p2s-settings.php';
require_once P2S_DIR . 'includes/class-p2s-alerts.php';
require_once P2S_DIR . 'includes/class-p2s-scanner.php';
require_once P2S_DIR . 'includes/class-p2s-monitor.php';
require_once P2S_DIR . 'includes/class-p2s-admin.php';

/**
 * Bootstrap, cron wiring, activation and deactivation.
 */
class P2S_Plugin {

	public static function boot() {
		add_filter( 'cron_schedules', array( __CLASS__, 'cron_schedules' ) );
		register_activation_hook( P2S_FILE, array( __CLASS__, 'activate' ) );
		register_deactivation_hook( P2S_FILE, array( __CLASS__, 'deactivate' ) );
		add_action( 'plugins_loaded', array( __CLASS__, 'init' ) );
	}

	public static function cron_schedules( $schedules ) {
		$schedules['p2s_15min'] = array(
			'interval' => 15 * MINUTE_IN_SECONDS,
			'display'  => __( 'Every 15 minutes', 'php2shell-guard' ),
		);
		return $schedules;
	}

	public static function init() {
		load_plugin_textdomain( 'php2shell-guard', false, dirname( plugin_basename( P2S_FILE ) ) . '/languages' );
		P2S_Monitor::init();
		add_action( 'p2s_scan', array( 'P2S_Scanner', 'cron_run' ) );
		add_action( 'init', array( __CLASS__, 'ensure_scheduled' ) );
		if ( is_admin() ) {
			P2S_Admin::init();
		}
	}

	/**
	 * Keeps the three cron events in place and in line with the settings.
	 */
	public static function ensure_scheduled() {
		if ( ! is_admin() && ! wp_doing_cron() ) {
			return;
		}
		$freq = P2S_Settings::get( 'scan_frequency' );
		if ( wp_get_schedule( 'p2s_scan' ) !== $freq ) {
			wp_clear_scheduled_hook( 'p2s_scan' );
			wp_schedule_event( time() + 300, $freq, 'p2s_scan' );
		}
		if ( ! wp_next_scheduled( 'p2s_watch' ) ) {
			wp_schedule_event( time() + 120, 'p2s_15min', 'p2s_watch' );
		}
		$beat = (bool) P2S_Settings::get( 'heartbeat' );
		if ( $beat && ! wp_next_scheduled( 'p2s_heartbeat' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'p2s_heartbeat' );
		} elseif ( ! $beat && wp_next_scheduled( 'p2s_heartbeat' ) ) {
			wp_clear_scheduled_hook( 'p2s_heartbeat' );
		}
	}

	public static function activate() {
		self::ensure_scheduled_force();
	}

	private static function ensure_scheduled_force() {
		$freq = P2S_Settings::get( 'scan_frequency' );
		if ( ! wp_next_scheduled( 'p2s_scan' ) ) {
			wp_schedule_event( time() + 120, $freq, 'p2s_scan' );
		}
		if ( ! wp_next_scheduled( 'p2s_watch' ) ) {
			wp_schedule_event( time() + 120, 'p2s_15min', 'p2s_watch' );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( 'p2s_scan' );
		wp_clear_scheduled_hook( 'p2s_watch' );
		wp_clear_scheduled_hook( 'p2s_heartbeat' );
		// Someone switching the guard off is itself worth knowing about.
		P2S_Monitor::report_deactivation();
	}
}

P2S_Plugin::boot();
