<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Plugin settings: defaults, getters and sanitising.
 */
class P2S_Settings {

	const OPTION = 'p2s_settings';

	public static function defaults() {
		return array(
			'since'          => '2026-10-17', // First known exploitation.
			'email_enabled'  => 1,
			'emails'         => '',           // Empty = the site admin email.
			'webhook_url'    => '',
			'webhook_format' => 'slack',
			'telegram_token' => '',
			'telegram_chat'  => '',
			'alert_review'   => 0,
			'scan_frequency' => 'daily',
			'heartbeat'      => 0,
			'log_paths'      => '',
		);
	}

	public static function all() {
		$o = get_option( self::OPTION, array() );
		if ( ! is_array( $o ) ) {
			$o = array();
		}
		return wp_parse_args( $o, self::defaults() );
	}

	public static function get( $key ) {
		$all = self::all();
		return isset( $all[ $key ] ) ? $all[ $key ] : null;
	}

	/**
	 * Alert recipients: configured list, or the site admin email.
	 */
	public static function recipients() {
		$list = array_filter( array_map( 'trim', explode( ',', (string) self::get( 'emails' ) ) ) );
		if ( ! $list ) {
			$list = array( (string) get_option( 'admin_email' ) );
		}
		return array_values( array_filter( $list, 'is_email' ) );
	}

	public static function sanitize( $in ) {
		$in  = is_array( $in ) ? $in : array();
		$def = self::defaults();
		$out = array();

		$since        = isset( $in['since'] ) ? trim( (string) $in['since'] ) : $def['since'];
		$out['since'] = ( preg_match( '/^\d{4}-\d{2}-\d{2}$/', $since ) && strtotime( $since ) ) ? $since : $def['since'];

		$out['email_enabled'] = empty( $in['email_enabled'] ) ? 0 : 1;

		$emails = array();
		if ( isset( $in['emails'] ) ) {
			foreach ( preg_split( '/[\s,;]+/', (string) $in['emails'], -1, PREG_SPLIT_NO_EMPTY ) as $e ) {
				$e = sanitize_email( $e );
				if ( $e && is_email( $e ) ) {
					$emails[] = $e;
				}
			}
		}
		$out['emails'] = implode( ', ', array_unique( $emails ) );

		$url                = isset( $in['webhook_url'] ) ? trim( (string) $in['webhook_url'] ) : '';
		$out['webhook_url'] = '' === $url ? '' : esc_url_raw( $url, array( 'https', 'http' ) );

		$fmt                   = isset( $in['webhook_format'] ) ? (string) $in['webhook_format'] : 'slack';
		$out['webhook_format'] = in_array( $fmt, array( 'slack', 'discord', 'generic' ), true ) ? $fmt : 'slack';

		$out['telegram_token'] = isset( $in['telegram_token'] ) ? preg_replace( '/[^0-9A-Za-z:_-]/', '', (string) $in['telegram_token'] ) : '';
		$out['telegram_chat']  = isset( $in['telegram_chat'] ) ? preg_replace( '/[^0-9A-Za-z@_-]/', '', (string) $in['telegram_chat'] ) : '';

		$out['alert_review'] = empty( $in['alert_review'] ) ? 0 : 1;
		$out['heartbeat']    = empty( $in['heartbeat'] ) ? 0 : 1;

		$freq                  = isset( $in['scan_frequency'] ) ? (string) $in['scan_frequency'] : 'daily';
		$out['scan_frequency'] = in_array( $freq, array( 'hourly', 'twicedaily', 'daily' ), true ) ? $freq : 'daily';

		$out['log_paths'] = isset( $in['log_paths'] ) ? sanitize_textarea_field( (string) $in['log_paths'] ) : '';

		return $out;
	}
}
