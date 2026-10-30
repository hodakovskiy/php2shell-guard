<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Admin UI: status page, event log, settings, scan AJAX.
 */
class P2S_Admin {

	const SLUG = 'php2shell-guard';

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_action( 'admin_notices', array( __CLASS__, 'banner' ) );
		add_action( 'wp_ajax_p2s_scan_step', array( __CLASS__, 'ajax_scan_step' ) );
		add_action( 'admin_post_p2s_ack', array( __CLASS__, 'handle_ack' ) );
		add_action( 'admin_post_p2s_ack_event', array( __CLASS__, 'handle_ack_event' ) );
		add_action( 'admin_post_p2s_accept_baseline', array( __CLASS__, 'handle_accept_baseline' ) );
		add_action( 'admin_post_p2s_test_alert', array( __CLASS__, 'handle_test_alert' ) );
		add_action( 'admin_post_p2s_reset_ack', array( __CLASS__, 'handle_reset_ack' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( P2S_FILE ), array( __CLASS__, 'action_links' ) );
		add_filter( 'plugin_row_meta', array( __CLASS__, 'row_meta' ), 10, 2 );
	}

	public static function menu() {
		add_menu_page(
			__( 'PHP2Shell Guard', 'php2shell-guard' ),
			__( 'PHP2Shell Guard', 'php2shell-guard' ),
			'manage_options',
			self::SLUG,
			array( __CLASS__, 'render' ),
			'dashicons-shield-alt',
			81
		);
	}

	public static function register_settings() {
		register_setting(
			'p2s_settings_group',
			P2S_Settings::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( 'P2S_Settings', 'sanitize' ),
			)
		);
	}

	public static function assets( $hook ) {
		if ( 'toplevel_page_' . self::SLUG !== $hook ) {
			return;
		}
		wp_enqueue_style( 'p2s-admin', P2S_URL . 'assets/admin.css', array(), P2S_VERSION );
		wp_enqueue_script( 'p2s-admin', P2S_URL . 'assets/admin.js', array(), P2S_VERSION, true );
		$steps = array();
		foreach ( P2S_Scanner::checks() as $id => $label ) {
			$steps[] = array( 'id' => $id, 'label' => $label );
		}
		wp_localize_script(
			'p2s-admin',
			'P2S',
			array(
				'ajax'  => admin_url( 'admin-ajax.php' ),
				'nonce' => wp_create_nonce( 'p2s_scan' ),
				'steps' => $steps,
				'i18n'  => array(
					'done'  => __( 'Scan complete. Reloading...', 'php2shell-guard' ),
					'error' => __( 'Request failed', 'php2shell-guard' ),
				),
			)
		);
	}

	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( admin_url( 'admin.php?page=' . self::SLUG ) ) . '">' . esc_html__( 'Open', 'php2shell-guard' ) . '</a>' );
		return $links;
	}

	public static function row_meta( $links, $file ) {
		if ( plugin_basename( P2S_FILE ) !== $file ) {
			return $links;
		}
		if ( defined( 'P2S_CONTACT_URL' ) && P2S_CONTACT_URL ) {
			$links[] = '<a href="' . esc_url( P2S_CONTACT_URL ) . '" target="_blank" rel="noopener">' . esc_html__( 'Get help', 'php2shell-guard' ) . '</a>';
		} elseif ( defined( 'P2S_CONTACT_EMAIL' ) && P2S_CONTACT_EMAIL && is_email( P2S_CONTACT_EMAIL ) ) {
			$links[] = '<a href="mailto:' . esc_attr( P2S_CONTACT_EMAIL ) . '">' . esc_html__( 'Get help', 'php2shell-guard' ) . '</a>';
		}
		return $links;
	}

	/* ==================================================================
	 * Banner shown on every admin page while something critical is open
	 * ================================================================ */

	public static function banner() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$n = count( P2S_Scanner::open_findings( array( 'critical' ) ) ) + P2S_Alerts::unacked_critical_events();
		if ( $n < 1 ) {
			return;
		}
		printf(
			'<div class="notice notice-error"><p><strong>%s</strong> %s <a href="%s">%s</a></p></div>',
			esc_html__( 'PHP2Shell Guard:', 'php2shell-guard' ),
			esc_html(
				sprintf(
					/* translators: %d: number of critical items */
					_n( '%d critical item needs your attention.', '%d critical items need your attention.', $n, 'php2shell-guard' ),
					$n
				)
			),
			esc_url( admin_url( 'admin.php?page=' . self::SLUG ) ),
			esc_html__( 'Review now', 'php2shell-guard' )
		);
		echo '</div>';
	}

	/* ==================================================================
	 * AJAX scan
	 * ================================================================ */

	public static function ajax_scan_step() {
		check_ajax_referer( 'p2s_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
		}
		@ignore_user_abort( true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		@set_time_limit( 120 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

		$step   = isset( $_POST['step'] ) ? sanitize_key( wp_unslash( $_POST['step'] ) ) : '';
		$offset = isset( $_POST['offset'] ) ? absint( $_POST['offset'] ) : 0;

		if ( 'finish' === $step ) {
			P2S_Scanner::finish();
			wp_send_json_success( array( 'next' => null ) );
		}
		$scanner = new P2S_Scanner( 25 );
		$r       = $scanner->run_check( $step, $offset );
		wp_send_json_success( array( 'next' => $r['next'] ) );
	}

	/* ==================================================================
	 * Form handlers
	 * ================================================================ */

	private static function guard( $action ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'php2shell-guard' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $action );
	}

	private static function back( $tab, $msg ) {
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'    => self::SLUG,
					'tab'     => $tab,
					'p2s_msg' => $msg,
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	public static function handle_ack() {
		self::guard( 'p2s_ack' );
		$fp = isset( $_POST['fp'] ) ? preg_replace( '/[^a-f0-9]/', '', (string) wp_unslash( $_POST['fp'] ) ) : '';
		if ( '' !== $fp ) {
			$a = get_option( 'p2s_ack', array() );
			$a = is_array( $a ) ? $a : array();
			$a[ $fp ] = time();
			update_option( 'p2s_ack', $a, false );
		}
		self::back( 'status', 'acked' );
	}

	public static function handle_ack_event() {
		self::guard( 'p2s_ack_event' );
		$id = isset( $_POST['event_id'] ) ? preg_replace( '/[^a-zA-Z0-9-]/', '', (string) wp_unslash( $_POST['event_id'] ) ) : '';
		if ( '' !== $id ) {
			P2S_Alerts::ack_event( $id );
		}
		self::back( 'events', 'acked' );
	}

	public static function handle_accept_baseline() {
		self::guard( 'p2s_accept_baseline' );
		P2S_Monitor::accept_baseline();
		self::back( 'status', 'baseline' );
	}

	public static function handle_reset_ack() {
		self::guard( 'p2s_reset_ack' );
		delete_option( 'p2s_ack' );
		delete_option( 'p2s_notified' );
		self::back( 'status', 'reset' );
	}

	public static function handle_test_alert() {
		self::guard( 'p2s_test_alert' );
		$res = P2S_Alerts::send(
			__( 'Test alert', 'php2shell-guard' ),
			array( __( 'This is a test from PHP2Shell Guard. If you can read this, alerts reach you.', 'php2shell-guard' ) ),
			'info'
		);
		$bad = array();
		foreach ( $res as $ch => $r ) {
			if ( true !== $r ) {
				$bad[] = $ch;
			}
		}
		self::back( 'settings', $res && ! $bad ? 'test_ok' : 'test_fail' );
	}

	/* ==================================================================
	 * Rendering
	 * ================================================================ */

	private static function badge( $level ) {
		$labels = array(
			'critical' => __( 'Critical', 'php2shell-guard' ),
			'review'   => __( 'Review', 'php2shell-guard' ),
			'ok'       => __( 'OK', 'php2shell-guard' ),
			'info'     => __( 'Info', 'php2shell-guard' ),
		);
		$l = isset( $labels[ $level ] ) ? $level : 'info';
		return '<span class="p2s-badge p2s-' . esc_attr( $l ) . '">' . esc_html( $labels[ $l ] ) . '</span>';
	}

	private static function post_button( $action, $label, array $fields = array(), $class = 'button' ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="p2s-inline">';
		echo '<input type="hidden" name="action" value="' . esc_attr( $action ) . '">';
		foreach ( $fields as $k => $v ) {
			echo '<input type="hidden" name="' . esc_attr( $k ) . '" value="' . esc_attr( $v ) . '">';
		}
		wp_nonce_field( $action );
		echo '<button type="submit" class="' . esc_attr( $class ) . '">' . esc_html( $label ) . '</button></form>';
	}

	public static function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$tab  = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'status'; // phpcs:ignore WordPress.Security.NonceVerification
		$tabs = array(
			'status'   => __( 'Status', 'php2shell-guard' ),
			'events'   => __( 'Live events', 'php2shell-guard' ),
			'settings' => __( 'Alerts & settings', 'php2shell-guard' ),
		);
		if ( ! isset( $tabs[ $tab ] ) ) {
			$tab = 'status';
		}

		echo '<div class="wrap p2s-wrap"><h1>' . esc_html__( 'PHP2Shell Guard', 'php2shell-guard' ) . '</h1>';
		self::flash();
		echo '<nav class="nav-tab-wrapper">';
		foreach ( $tabs as $k => $label ) {
			printf(
				'<a href="%s" class="nav-tab %s">%s</a>',
				esc_url( admin_url( 'admin.php?page=' . self::SLUG . '&tab=' . $k ) ),
				$k === $tab ? 'nav-tab-active' : '',
				esc_html( $label )
			);
		}
		echo '</nav>';

		if ( 'events' === $tab ) {
			self::render_events();
		} elseif ( 'settings' === $tab ) {
			self::render_settings();
		} else {
			self::render_status();
		}
		self::render_footer();
		echo '</div>';
	}

	private static function flash() {
		$msg = isset( $_GET['p2s_msg'] ) ? sanitize_key( wp_unslash( $_GET['p2s_msg'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		$map = array(
			'acked'     => array( 'success', __( 'Acknowledged.', 'php2shell-guard' ) ),
			'baseline'  => array( 'success', __( 'Current state accepted as the new baseline.', 'php2shell-guard' ) ),
			'reset'     => array( 'success', __( 'Acknowledgements cleared.', 'php2shell-guard' ) ),
			'test_ok'   => array( 'success', __( 'Test alert sent through every configured channel. Check that it arrived.', 'php2shell-guard' ) ),
			'test_fail' => array( 'error', __( 'At least one channel failed. See the alert log below.', 'php2shell-guard' ) ),
		);
		if ( isset( $map[ $msg ] ) ) {
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', esc_attr( $map[ $msg ][0] ), esc_html( $map[ $msg ][1] ) );
		}
		if ( ! empty( $_GET['settings-updated'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			printf( '<div class="notice notice-success is-dismissible"><p>%s</p></div>', esc_html__( 'Settings saved.', 'php2shell-guard' ) );
		}
	}

	private static function render_status() {
		$r     = P2S_Scanner::results();
		$ack   = get_option( 'p2s_ack', array() );
		$ack   = is_array( $ack ) ? $ack : array();
		$crit  = count( P2S_Scanner::open_findings( array( 'critical' ) ) );
		$rev   = count( P2S_Scanner::open_findings( array( 'review' ) ) );
		$base  = P2S_Monitor::get_baseline();
		$last  = ! empty( $r['last_full'] ) ? sprintf( /* translators: %s: time span, e.g. "3 hours" */ __( '%s ago', 'php2shell-guard' ), human_time_diff( (int) $r['last_full'] ) ) : __( 'never', 'php2shell-guard' );
		$next  = wp_next_scheduled( 'p2s_scan' );

		echo '<div class="p2s-summary">';
		printf( '<div class="p2s-stat p2s-%s"><b>%d</b><span>%s</span></div>', $crit ? 'critical' : 'ok', (int) $crit, esc_html__( 'critical', 'php2shell-guard' ) );
		printf( '<div class="p2s-stat p2s-%s"><b>%d</b><span>%s</span></div>', $rev ? 'review' : 'ok', (int) $rev, esc_html__( 'to review', 'php2shell-guard' ) );
		printf( '<div class="p2s-stat"><b>%s</b><span>%s</span></div>', esc_html( $last ), esc_html__( 'last full scan', 'php2shell-guard' ) );
		printf( '<div class="p2s-stat"><b>%s</b><span>%s</span></div>', $next ? esc_html( human_time_diff( time(), $next ) ) : '-', esc_html__( 'until next scan', 'php2shell-guard' ) );
		echo '</div>';

		echo '<p class="p2s-actions">';
		echo '<button type="button" class="button button-primary" id="p2s-run">' . esc_html__( 'Run full scan', 'php2shell-guard' ) . '</button> ';
		self::post_button( 'p2s_accept_baseline', __( 'Accept current state', 'php2shell-guard' ) );
		if ( $ack ) {
			self::post_button( 'p2s_reset_ack', __( 'Clear acknowledgements', 'php2shell-guard' ) );
		}
		echo '</p>';
		echo '<div id="p2s-progress" aria-live="polite"></div>';

		echo '<p class="description">';
		if ( $base ) {
			printf(
				/* translators: %s: time since baseline */
				esc_html__( 'Real-time watch is active. Baseline set %s ago: changes to wp-config.php, .htaccess, .user.ini, must-use plugins and the list of administrators raise an alert. Use "Accept current state" after legitimate changes.', 'php2shell-guard' ),
				esc_html( human_time_diff( (int) $base['time'] ) )
			);
		} else {
			esc_html_e( 'No baseline yet. It is taken automatically after the first scan that finds nothing critical. Until then only uploads and live events are watched. Fix any critical findings first, then run a scan or click "Accept current state".', 'php2shell-guard' );
		}
		echo '</p>';

		if ( $crit > 0 ) {
			self::render_contact();
		}

		if ( empty( $r['checks'] ) ) {
			echo '<p>' . esc_html__( 'No scan has run yet. Click "Run full scan".', 'php2shell-guard' ) . '</p>';
			return;
		}

		foreach ( P2S_Scanner::checks() as $id => $label ) {
			if ( empty( $r['checks'][ $id ] ) ) {
				continue;
			}
			$c = $r['checks'][ $id ];
			echo '<div class="p2s-section"><h2>' . esc_html( $label ) . ' <small>' . esc_html( sprintf( /* translators: %s: time span, e.g. "3 hours" */ __( '%s ago', 'php2shell-guard' ), human_time_diff( (int) $c['time'] ) ) ) . '</small></h2>';
			foreach ( $c['findings'] as $f ) {
				$acked = isset( $ack[ $f['fp'] ] );
				echo '<div class="p2s-finding' . ( $acked ? ' p2s-acked' : '' ) . '">';
				echo self::badge( $f['level'] ) . ' <strong>' . esc_html( $f['title'] ) . '</strong>'; // phpcs:ignore WordPress.Security.EscapeOutput
				if ( '' !== $f['detail'] ) {
					echo '<p>' . esc_html( $f['detail'] ) . '</p>';
				}
				if ( ! empty( $f['items'] ) ) {
					echo '<details><summary>' . esc_html( sprintf( _n( '%d item', '%d items', count( $f['items'] ) + (int) $f['more'], 'php2shell-guard' ), count( $f['items'] ) + (int) $f['more'] ) ) . '</summary><pre>' . esc_html( implode( "\n", $f['items'] ) );
					if ( ! empty( $f['more'] ) ) {
						echo esc_html( "\n... " . sprintf( __( '%d more not shown', 'php2shell-guard' ), (int) $f['more'] ) );
					}
					echo '</pre></details>';
				}
				if ( in_array( $f['level'], array( 'critical', 'review' ), true ) ) {
					if ( $acked ) {
						echo '<em class="p2s-muted">' . esc_html__( 'Acknowledged', 'php2shell-guard' ) . '</em>';
					} else {
						self::post_button( 'p2s_ack', __( 'Acknowledge', 'php2shell-guard' ), array( 'fp' => $f['fp'] ), 'button button-small' );
					}
				}
				echo '</div>';
			}
			echo '</div>';
		}
	}

	private static function render_contact() {
		$name  = defined( 'P2S_CONTACT_NAME' ) ? P2S_CONTACT_NAME : '';
		$email = defined( 'P2S_CONTACT_EMAIL' ) ? P2S_CONTACT_EMAIL : '';
		$url   = defined( 'P2S_CONTACT_URL' ) ? P2S_CONTACT_URL : '';
		if ( '' === $name && '' === $email && '' === $url ) {
			return;
		}
		echo '<div class="p2s-contact"><strong>' . esc_html__( 'Need help cleaning up?', 'php2shell-guard' ) . '</strong> ';
		if ( '' !== $name ) {
			echo esc_html( $name ) . ' ';
		}
		if ( '' !== $email && is_email( $email ) ) {
			echo '<a href="mailto:' . esc_attr( $email ) . '">' . esc_html( $email ) . '</a> ';
		}
		if ( '' !== $url ) {
			echo '<a href="' . esc_url( $url ) . '" target="_blank" rel="noopener">' . esc_html( $url ) . '</a>';
		}
		echo '</div>';
	}

	private static function render_events() {
		$ev = P2S_Alerts::events();
		echo '<h2>' . esc_html__( 'Live events', 'php2shell-guard' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Things the guard saw as they happened: new administrators, changed site URL or admin email, PHP uploads, edits to critical files.', 'php2shell-guard' ) . '</p>';
		if ( ! $ev ) {
			echo '<p>' . esc_html__( 'Nothing recorded yet.', 'php2shell-guard' ) . '</p>';
		} else {
			if ( P2S_Alerts::unacked_critical_events() ) {
				self::post_button( 'p2s_ack_event', __( 'Acknowledge all', 'php2shell-guard' ), array( 'event_id' => 'all' ) );
			}
			echo '<table class="widefat striped p2s-events"><thead><tr><th>' . esc_html__( 'Time (UTC)', 'php2shell-guard' ) . '</th><th>' . esc_html__( 'Level', 'php2shell-guard' ) . '</th><th>' . esc_html__( 'Event', 'php2shell-guard' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( $ev as $e ) {
				echo '<tr' . ( ! empty( $e['ack'] ) ? ' class="p2s-acked"' : '' ) . '><td>' . esc_html( gmdate( 'Y-m-d H:i:s', (int) $e['time'] ) ) . '</td><td>' . self::badge( $e['level'] ) . '</td><td><strong>' . esc_html( $e['title'] ) . '</strong><pre>' . esc_html( implode( "\n", (array) $e['lines'] ) ) . '</pre></td><td>'; // phpcs:ignore WordPress.Security.EscapeOutput
				if ( empty( $e['ack'] ) ) {
					self::post_button( 'p2s_ack_event', __( 'Acknowledge', 'php2shell-guard' ), array( 'event_id' => $e['id'] ), 'button button-small' );
				}
				echo '</td></tr>';
			}
			echo '</tbody></table>';
		}

		echo '<h2>' . esc_html__( 'Alert delivery log', 'php2shell-guard' ) . '</h2>';
		$log = P2S_Alerts::alert_log();
		if ( ! $log ) {
			echo '<p>' . esc_html__( 'No alerts have been sent yet.', 'php2shell-guard' ) . '</p>';
			return;
		}
		echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Time (UTC)', 'php2shell-guard' ) . '</th><th>' . esc_html__( 'Subject', 'php2shell-guard' ) . '</th><th>' . esc_html__( 'Delivery', 'php2shell-guard' ) . '</th></tr></thead><tbody>';
		foreach ( $log as $l ) {
			$parts = array();
			foreach ( (array) $l['result'] as $ch => $r ) {
				$parts[] = esc_html( $ch ) . ': ' . ( true === $r ? '<span class="p2s-okc">OK</span>' : '<span class="p2s-errc">' . esc_html( (string) $r ) . '</span>' );
			}
			echo '<tr><td>' . esc_html( gmdate( 'Y-m-d H:i:s', (int) $l['time'] ) ) . '</td><td>' . esc_html( $l['subject'] ) . '</td><td>' . ( $parts ? implode( '<br>', $parts ) : esc_html__( 'no channel configured', 'php2shell-guard' ) ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput
		}
		echo '</tbody></table>';
	}

	private static function render_settings() {
		$s = P2S_Settings::all();
		$o = P2S_Settings::OPTION;
		echo '<form method="post" action="options.php">';
		settings_fields( 'p2s_settings_group' );
		echo '<table class="form-table" role="presentation">';

		echo '<tr><th>' . esc_html__( 'Email alerts', 'php2shell-guard' ) . '</th><td>';
		printf( '<label><input type="checkbox" name="%s[email_enabled]" value="1" %s> %s</label><br>', esc_attr( $o ), checked( ! empty( $s['email_enabled'] ), true, false ), esc_html__( 'Send alerts by email', 'php2shell-guard' ) );
		printf( '<textarea name="%s[emails]" rows="2" class="large-text" placeholder="%s">%s</textarea>', esc_attr( $o ), esc_attr( (string) get_option( 'admin_email' ) ), esc_textarea( $s['emails'] ) );
		echo '<p class="description">' . esc_html__( 'Comma or line separated. Empty means the site administrator email. Many hosts send WordPress mail unreliably, so also set up a webhook or Telegram.', 'php2shell-guard' ) . '</p></td></tr>';

		echo '<tr><th>' . esc_html__( 'Webhook', 'php2shell-guard' ) . '</th><td>';
		printf( '<input type="url" name="%s[webhook_url]" value="%s" class="large-text" placeholder="https://hooks.slack.com/services/...">', esc_attr( $o ), esc_attr( $s['webhook_url'] ) );
		echo '<br><select name="' . esc_attr( $o ) . '[webhook_format]">';
		foreach ( array( 'slack' => 'Slack-compatible ({"text": ...})', 'discord' => 'Discord ({"content": ...})', 'generic' => __( 'Generic JSON (structured)', 'php2shell-guard' ) ) as $k => $label ) {
			printf( '<option value="%s" %s>%s</option>', esc_attr( $k ), selected( $s['webhook_format'], $k, false ), esc_html( $label ) );
		}
		echo '</select></td></tr>';

		echo '<tr><th>' . esc_html__( 'Telegram', 'php2shell-guard' ) . '</th><td>';
		printf( '<input type="text" name="%s[telegram_token]" value="%s" class="regular-text" placeholder="Bot token" autocomplete="off"> ', esc_attr( $o ), esc_attr( $s['telegram_token'] ) );
		printf( '<input type="text" name="%s[telegram_chat]" value="%s" class="regular-text" placeholder="Chat ID" autocomplete="off">', esc_attr( $o ), esc_attr( $s['telegram_chat'] ) );
		echo '<p class="description">' . esc_html__( 'Create a bot with @BotFather, send it a message, and use your chat ID. The token is stored in the database like any plugin setting.', 'php2shell-guard' ) . '</p></td></tr>';

		echo '<tr><th>' . esc_html__( 'Also alert on "review" items', 'php2shell-guard' ) . '</th><td>';
		printf( '<label><input type="checkbox" name="%s[alert_review]" value="1" %s> %s</label>', esc_attr( $o ), checked( ! empty( $s['alert_review'] ), true, false ), esc_html__( 'Notify about items that need a human look, not only critical ones (noisier)', 'php2shell-guard' ) );
		echo '</td></tr>';

		echo '<tr><th>' . esc_html__( 'Scan frequency', 'php2shell-guard' ) . '</th><td><select name="' . esc_attr( $o ) . '[scan_frequency]">';
		foreach ( array( 'hourly' => __( 'Hourly', 'php2shell-guard' ), 'twicedaily' => __( 'Twice daily', 'php2shell-guard' ), 'daily' => __( 'Daily', 'php2shell-guard' ) ) as $k => $label ) {
			printf( '<option value="%s" %s>%s</option>', esc_attr( $k ), selected( $s['scan_frequency'], $k, false ), esc_html( $label ) );
		}
		echo '</select><p class="description">' . esc_html__( 'The watcher for critical files and administrators runs every 15 minutes regardless. These timers rely on WP-Cron; on low-traffic sites trigger wp-cron.php from a real cron job.', 'php2shell-guard' ) . '</p></td></tr>';

		echo '<tr><th>' . esc_html__( 'Inspect changes since', 'php2shell-guard' ) . '</th><td>';
		printf( '<input type="date" name="%s[since]" value="%s"><p class="description">%s</p>', esc_attr( $o ), esc_attr( $s['since'] ), esc_html__( 'Start of the window to inspect (first known exploitation).', 'php2shell-guard' ) );
		echo '</td></tr>';

		echo '<tr><th>' . esc_html__( 'Log files', 'php2shell-guard' ) . '</th><td>';
		printf( '<textarea name="%s[log_paths]" rows="3" class="large-text code" placeholder="/var/log/nginx/access.log&#10;/home/user/logs/*">%s</textarea>', esc_attr( $o ), esc_textarea( $s['log_paths'] ) );
		echo '<p class="description">' . esc_html__( 'Optional. One path or glob per line. Leave empty to look in the usual places. PHP often cannot read server logs; ask your host if nothing is found.', 'php2shell-guard' ) . '</p></td></tr>';

		echo '<tr><th>' . esc_html__( 'Daily heartbeat', 'php2shell-guard' ) . '</th><td>';
		printf( '<label><input type="checkbox" name="%s[heartbeat]" value="1" %s> %s</label>', esc_attr( $o ), checked( ! empty( $s['heartbeat'] ), true, false ), esc_html__( 'Send a daily "I am alive" message', 'php2shell-guard' ) );
		echo '<p class="description">' . esc_html__( 'If the message stops, the guard may have been switched off. This is how you notice a silent failure.', 'php2shell-guard' ) . '</p></td></tr>';

		echo '</table>';
		submit_button();
		echo '</form>';

		echo '<h2>' . esc_html__( 'Test', 'php2shell-guard' ) . '</h2>';
		self::post_button( 'p2s_test_alert', __( 'Send a test alert', 'php2shell-guard' ) );
		echo '<p class="description">' . esc_html__( 'Save your settings first, then send a test.', 'php2shell-guard' ) . '</p>';
	}

	private static function render_footer() {
		echo '<hr><p class="description">';
		esc_html_e( 'PHP2Shell Guard only reads and reports. It never modifies or deletes files. It cannot see inside your server beyond what PHP can read, and an attacker with full code execution could tamper with any plugin, so treat a clean result as "no signs found", not as proof.', 'php2shell-guard' );
		echo '</p>';
	}
}
