<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Delivers alerts (email, webhook, Telegram) and keeps the event log.
 */
class P2S_Alerts {

	const MAX_EVENTS     = 100;
	const MAX_ALERT_LOG  = 30;
	const RT_PER_HOUR    = 10;
	const RT_DEDUP_SECS  = 600;

	/* ------------------------------------------------------------------
	 * Sending
	 * ---------------------------------------------------------------- */

	/**
	 * Sends one alert through every configured channel.
	 *
	 * @param string   $subject Short headline.
	 * @param string[] $lines   Body lines.
	 * @param string   $level   critical|review|info.
	 * @return array Channel => true|string(error).
	 */
	public static function send( $subject, array $lines, $level = 'critical' ) {
		$s      = P2S_Settings::all();
		$site   = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		$url    = admin_url( 'admin.php?page=php2shell-guard' );
		$result = array();

		$body  = $subject . "\n\n";
		/* translators: %s: site address */
		$body .= sprintf( __( 'Site: %s', 'php2shell-guard' ), home_url() ) . "\n";
		/* translators: %s: date and time in UTC */
		$body .= sprintf( __( 'Time: %s UTC', 'php2shell-guard' ), gmdate( 'Y-m-d H:i:s' ) ) . "\n\n";
		$body .= implode( "\n", $lines ) . "\n\n";
		/* translators: %s: admin page URL */
		$body .= sprintf( __( 'Review and acknowledge: %s', 'php2shell-guard' ), $url ) . "\n";

		$text = mb_substr( '[' . $site . '] ' . $body, 0, 3500 );

		if ( ! empty( $s['email_enabled'] ) ) {
			$to = P2S_Settings::recipients();
			if ( $to ) {
				$mail_body = $body;
				$footer    = self::contact_footer();
				if ( '' !== $footer ) {
					$mail_body .= "\n-- \n" . $footer . "\n";
				}
				$ok                = wp_mail( $to, '[PHP2Shell Guard] ' . $subject . ' - ' . $site, $mail_body );
				$result['email'] = $ok ? true : __( 'wp_mail() returned false', 'php2shell-guard' );
			} else {
				$result['email'] = __( 'no valid recipient', 'php2shell-guard' );
			}
		}

		if ( ! empty( $s['webhook_url'] ) ) {
			$result['webhook'] = self::post_webhook( $s['webhook_url'], $s['webhook_format'], $subject, $lines, $level, $text );
		}

		if ( ! empty( $s['telegram_token'] ) && ! empty( $s['telegram_chat'] ) ) {
			$resp = wp_safe_remote_post(
				'https://api.telegram.org/bot' . $s['telegram_token'] . '/sendMessage',
				array(
					'timeout' => 10,
					'body'    => array(
						'chat_id'                  => $s['telegram_chat'],
						'text'                     => $text,
						'disable_web_page_preview' => 'true',
					),
				)
			);
			$result['telegram'] = self::http_ok( $resp );
		}

		self::log_alert( $subject, $level, $result );
		return $result;
	}

	private static function post_webhook( $url, $format, $subject, array $lines, $level, $text ) {
		if ( 'discord' === $format ) {
			$payload = array( 'content' => mb_substr( $text, 0, 1900 ) );
		} elseif ( 'generic' === $format ) {
			$payload = array(
				'source'  => 'php2shell-guard',
				'site'    => home_url(),
				'level'   => $level,
				'subject' => $subject,
				'lines'   => $lines,
				'time'    => gmdate( 'c' ),
				'url'     => admin_url( 'admin.php?page=php2shell-guard' ),
			);
		} else {
			$payload = array( 'text' => $text );
		}
		$resp = wp_safe_remote_post(
			$url,
			array(
				'timeout' => 10,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode( $payload ),
			)
		);
		return self::http_ok( $resp );
	}

	private static function http_ok( $resp ) {
		if ( is_wp_error( $resp ) ) {
			return $resp->get_error_message();
		}
		$code = (int) wp_remote_retrieve_response_code( $resp );
		return ( $code >= 200 && $code < 300 ) ? true : 'HTTP ' . $code;
	}

	private static function contact_footer() {
		$bits = array();
		if ( defined( 'P2S_CONTACT_NAME' ) && P2S_CONTACT_NAME ) {
			/* translators: %s: contact person or company */
			$bits[] = sprintf( __( 'Need help cleaning up? Contact %s', 'php2shell-guard' ), P2S_CONTACT_NAME );
		}
		if ( defined( 'P2S_CONTACT_EMAIL' ) && P2S_CONTACT_EMAIL ) {
			$bits[] = P2S_CONTACT_EMAIL;
		}
		if ( defined( 'P2S_CONTACT_URL' ) && P2S_CONTACT_URL ) {
			$bits[] = P2S_CONTACT_URL;
		}
		return implode( ' | ', $bits );
	}

	/* ------------------------------------------------------------------
	 * Real-time events
	 * ---------------------------------------------------------------- */

	/**
	 * Records an event and alerts, with de-duplication and a flood limit so
	 * an attack cannot turn the guard into a mail bomb.
	 */
	public static function event( $level, $key, $title, array $lines ) {
		self::record( $level, $title, $lines );

		$s = P2S_Settings::all();
		if ( 'critical' !== $level && ! ( 'review' === $level && ! empty( $s['alert_review'] ) ) ) {
			return;
		}

		$dk = 'p2s_dd_' . md5( $key );
		if ( get_transient( $dk ) ) {
			return;
		}
		set_transient( $dk, 1, self::RT_DEDUP_SECS );

		$st = get_transient( 'p2s_rt' );
		if ( ! is_array( $st ) || $st['t'] < time() - HOUR_IN_SECONDS ) {
			$st = array( 't' => time(), 'n' => 0 );
		}
		$st['n']++;
		set_transient( 'p2s_rt', $st, HOUR_IN_SECONDS );

		if ( $st['n'] > self::RT_PER_HOUR + 1 ) {
			return;
		}
		if ( $st['n'] === self::RT_PER_HOUR + 1 ) {
			self::send(
				__( 'Alert flood: further alerts suppressed for this hour', 'php2shell-guard' ),
				/* translators: %d: maximum alerts per hour */
				array( sprintf( __( 'More than %d alerts were raised within an hour. The rest are still recorded on the Live events tab.', 'php2shell-guard' ), self::RT_PER_HOUR ) ),
				'critical'
			);
			return;
		}
		self::send( $title, $lines, $level );
	}

	private static function record( $level, $title, array $lines ) {
		$ev = get_option( 'p2s_events', array() );
		if ( ! is_array( $ev ) ) {
			$ev = array();
		}
		array_unshift(
			$ev,
			array(
				'id'    => wp_generate_uuid4(),
				'time'  => time(),
				'level' => $level,
				'title' => $title,
				'lines' => array_slice( $lines, 0, 40 ),
				'ack'   => 0,
			)
		);
		update_option( 'p2s_events', array_slice( $ev, 0, self::MAX_EVENTS ), false );
	}

	public static function events() {
		$ev = get_option( 'p2s_events', array() );
		return is_array( $ev ) ? $ev : array();
	}

	public static function unacked_critical_events() {
		$n = 0;
		foreach ( self::events() as $e ) {
			if ( 'critical' === $e['level'] && empty( $e['ack'] ) ) {
				$n++;
			}
		}
		return $n;
	}

	public static function ack_event( $id ) {
		$ev = self::events();
		foreach ( $ev as &$e ) {
			if ( 'all' === $id || $e['id'] === $id ) {
				$e['ack'] = 1;
			}
		}
		unset( $e );
		update_option( 'p2s_events', $ev, false );
	}

	/* ------------------------------------------------------------------
	 * Scan alerts
	 * ---------------------------------------------------------------- */

	/**
	 * After a full scan: alerts once for each finding that is new since the
	 * last alert. Resolved findings are forgotten so they alert again if
	 * they come back.
	 */
	public static function process_scan() {
		$s      = P2S_Settings::all();
		$levels = ! empty( $s['alert_review'] ) ? array( 'critical', 'review' ) : array( 'critical' );
		$open   = P2S_Scanner::open_findings( $levels );

		$notified = get_option( 'p2s_notified', array() );
		if ( ! is_array( $notified ) ) {
			$notified = array();
		}
		$current = array();
		$new     = array();
		foreach ( $open as $f ) {
			$current[ $f['fp'] ] = 1;
			if ( ! isset( $notified[ $f['fp'] ] ) ) {
				$new[] = $f;
			}
		}
		$notified = array_intersect_key( $notified, $current );

		if ( $new ) {
			$crit  = 0;
			$lines = array();
			foreach ( $new as $f ) {
				if ( 'critical' === $f['level'] ) {
					$crit++;
				}
				$lines[] = '[' . ( 'critical' === $f['level'] ? __( 'CRITICAL', 'php2shell-guard' ) : __( 'REVIEW', 'php2shell-guard' ) ) . '] ' . $f['title'];
				if ( '' !== $f['detail'] ) {
					$lines[] = '    ' . $f['detail'];
				}
				foreach ( array_slice( $f['items'], 0, 5 ) as $it ) {
					$lines[] = '      - ' . $it;
				}
				if ( count( $f['items'] ) > 5 || ! empty( $f['more'] ) ) {
					$lines[] = '      ' . __( '... more on the admin page', 'php2shell-guard' );
				}
				$lines[] = '';
			}
			$host    = (string) wp_parse_url( home_url(), PHP_URL_HOST );
			$subject = $crit
				/* translators: 1: number of findings, 2: site host name */
				? sprintf( _n( '%1$d new critical finding on %2$s', '%1$d new critical findings on %2$s', $crit, 'php2shell-guard' ), $crit, $host )
				/* translators: 1: number of items, 2: site host name */
				: sprintf( _n( '%1$d new item to review on %2$s', '%1$d new items to review on %2$s', count( $new ), 'php2shell-guard' ), count( $new ), $host );
			self::send( $subject, $lines, $crit ? 'critical' : 'review' );
			foreach ( $new as $f ) {
				$notified[ $f['fp'] ] = time();
			}
		}
		update_option( 'p2s_notified', $notified, false );
	}

	/* ------------------------------------------------------------------
	 * Heartbeat
	 * ---------------------------------------------------------------- */

	public static function heartbeat() {
		$r    = P2S_Scanner::results();
		$last = ! empty( $r['last_full'] ) ? gmdate( 'Y-m-d H:i', (int) $r['last_full'] ) . ' UTC' : __( 'never', 'php2shell-guard' );
		self::send(
			__( 'Heartbeat: PHP2Shell Guard is running', 'php2shell-guard' ),
			array(
				/* translators: %s: date and time, or "never" */
				sprintf( __( 'Last full scan: %s', 'php2shell-guard' ), $last ),
				/* translators: %d: number */
				sprintf( __( 'Open critical findings: %d', 'php2shell-guard' ), count( P2S_Scanner::open_findings( array( 'critical' ) ) ) ),
				/* translators: %d: number */
				sprintf( __( 'Unacknowledged critical events: %d', 'php2shell-guard' ), self::unacked_critical_events() ),
				'',
				__( 'If you stop receiving this message, the guard may have been disabled. Check the site.', 'php2shell-guard' ),
			),
			'info'
		);
	}

	/* ------------------------------------------------------------------
	 * Alert log
	 * ---------------------------------------------------------------- */

	private static function log_alert( $subject, $level, array $result ) {
		$log = get_option( 'p2s_alert_log', array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}
		array_unshift(
			$log,
			array(
				'time'    => time(),
				'subject' => $subject,
				'level'   => $level,
				'result'  => $result,
			)
		);
		update_option( 'p2s_alert_log', array_slice( $log, 0, self::MAX_ALERT_LOG ), false );
	}

	public static function alert_log() {
		$log = get_option( 'p2s_alert_log', array() );
		return is_array( $log ) ? $log : array();
	}
}
