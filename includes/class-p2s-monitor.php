<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Real-time monitoring.
 *
 * Two layers:
 *  1. WordPress hooks that fire the moment something risky happens
 *     (new administrator, changed site URL, PHP file uploaded...).
 *  2. A 15-minute watcher that compares critical files and the list of
 *     administrators against a baseline. This also catches changes that
 *     bypass WordPress entirely (a user inserted straight into the database,
 *     a file edited over SSH).
 *
 * Nothing here modifies or deletes anything.
 */
class P2S_Monitor {

	const BASELINE = 'p2s_baseline';
	const SEEN     = 'p2s_seen';

	public static function init() {
		add_action( 'user_register', array( __CLASS__, 'on_user_register' ), 99 );
		add_action( 'set_user_role', array( __CLASS__, 'on_set_user_role' ), 99, 3 );
		add_action( 'add_user_role', array( __CLASS__, 'on_add_user_role' ), 99, 2 );
		add_action( 'updated_option', array( __CLASS__, 'on_updated_option' ), 99, 3 );
		add_filter( 'wp_handle_upload_prefilter', array( __CLASS__, 'on_upload' ), 1 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'on_upgrade' ), 99, 2 );
		add_action( 'p2s_watch', array( __CLASS__, 'watch' ) );
		add_action( 'p2s_heartbeat', array( 'P2S_Alerts', 'heartbeat' ) );
	}

	/* ==================================================================
	 * Context helpers
	 * ================================================================ */

	private static function context() {
		$u   = wp_get_current_user();
		$out = array();
		if ( $u && $u->exists() ) {
			/* translators: 1: user login, 2: user ID */
			$out[] = sprintf( __( 'Acting user: %1$s (ID %2$d)', 'php2shell-guard' ), $u->user_login, $u->ID );
		} elseif ( defined( 'WP_CLI' ) && WP_CLI ) {
			$out[] = __( 'Context: WP-CLI', 'php2shell-guard' );
		} elseif ( wp_doing_cron() ) {
			$out[] = __( 'Context: WP-Cron', 'php2shell-guard' );
		} else {
			$out[] = __( 'Acting user: nobody is logged in. This change came from an unauthenticated request, which is highly suspicious.', 'php2shell-guard' );
		}
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? filter_var( wp_unslash( $_SERVER['REMOTE_ADDR'] ), FILTER_VALIDATE_IP ) : false;
		if ( $ip ) {
			/* translators: %s: IP address */
			$out[] = sprintf( __( 'IP address: %s', 'php2shell-guard' ), $ip );
		}
		if ( isset( $_SERVER['REQUEST_URI'] ) ) {
			/* translators: %s: requested URL path */
			$out[] = sprintf( __( 'Request: %s', 'php2shell-guard' ), substr( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ), 0, 200 ) );
		}
		return $out;
	}

	/** True the first time a key is seen; used so one change alerts once. */
	public static function once( $key ) {
		$seen = get_option( self::SEEN, array() );
		if ( ! is_array( $seen ) ) {
			$seen = array();
		}
		$k = md5( $key );
		if ( isset( $seen[ $k ] ) ) {
			return false;
		}
		$pos          = strpos( $key, ':' );
		$seen[ $k ]   = array( 't' => time(), 'p' => false === $pos ? '' : substr( $key, 0, $pos ) );
		if ( count( $seen ) > 500 ) {
			uasort(
				$seen,
				function ( $a, $b ) {
					return $a['t'] - $b['t'];
				}
			);
			$seen = array_slice( $seen, 100, null, true );
		}
		update_option( self::SEEN, $seen, false );
		return true;
	}

	private static function forget_prefixes( array $prefixes ) {
		$seen = get_option( self::SEEN, array() );
		if ( ! is_array( $seen ) ) {
			return;
		}
		foreach ( $seen as $k => $v ) {
			if ( in_array( $v['p'], $prefixes, true ) ) {
				unset( $seen[ $k ] );
			}
		}
		update_option( self::SEEN, $seen, false );
	}

	/* ==================================================================
	 * Real-time hooks
	 * ================================================================ */

	private static function admin_created( $user_id, $how ) {
		$user_id = (int) $user_id;
		if ( ! self::once( 'admin:' . $user_id ) ) {
			return;
		}
		$u     = get_userdata( $user_id );
		$lines = array(
			/* translators: %s: how the role was obtained, e.g. "account created" */
			sprintf( __( 'A user now has the administrator role (%s).', 'php2shell-guard' ), $how ),
			/* translators: %s: user login, e-mail and ID */
			sprintf( __( 'New administrator: %s', 'php2shell-guard' ), $u ? $u->user_login . ' <' . $u->user_email . '> (ID ' . $user_id . ')' : 'ID ' . $user_id ),
		);
		$lines   = array_merge( $lines, self::context() );
		$lines[] = '';
		$lines[] = __( 'If you did not do this, treat the site as compromised: reset all passwords and secret keys, and remove the account.', 'php2shell-guard' );
		P2S_Alerts::event( 'critical', 'admin:' . $user_id, __( 'New administrator account', 'php2shell-guard' ), $lines );
	}

	public static function on_user_register( $user_id ) {
		$u = get_userdata( (int) $user_id );
		if ( $u && in_array( 'administrator', (array) $u->roles, true ) ) {
			self::admin_created( $user_id, __( 'account created', 'php2shell-guard' ) );
		}
	}

	public static function on_set_user_role( $user_id, $role, $old_roles ) {
		if ( 'administrator' === $role && ! in_array( 'administrator', (array) $old_roles, true ) ) {
			self::admin_created( $user_id, __( 'role changed', 'php2shell-guard' ) );
		}
	}

	public static function on_add_user_role( $user_id, $role ) {
		if ( 'administrator' === $role ) {
			self::admin_created( $user_id, __( 'role added', 'php2shell-guard' ) );
		}
	}

	public static function on_updated_option( $option, $old, $new ) {
		$watched = array( 'siteurl', 'home', 'admin_email', 'default_role', 'users_can_register' );
		if ( ! in_array( $option, $watched, true ) ) {
			return;
		}
		$old = is_scalar( $old ) ? (string) $old : __( '(complex value)', 'php2shell-guard' );
		$new = is_scalar( $new ) ? (string) $new : __( '(complex value)', 'php2shell-guard' );

		if ( 'users_can_register' === $option ) {
			if ( '1' !== $new ) {
				return;
			}
			$level = 'review';
			$title = __( 'Open registration was switched on', 'php2shell-guard' );
		} elseif ( 'default_role' === $option ) {
			if ( 'administrator' !== $new && 'editor' !== $new ) {
				return;
			}
			$level = 'administrator' === $new ? 'critical' : 'review';
			/* translators: %s: role name */
			$title = sprintf( __( 'Default role for new users was raised to %s', 'php2shell-guard' ), $new );
		} else {
			$level = 'critical';
			/* translators: %s: option name such as siteurl */
			$title = sprintf( __( 'Setting changed: %s', 'php2shell-guard' ), $option );
		}
		if ( ! self::once( 'opt:' . $option . '|' . $new ) ) {
			return;
		}
		$lines   = array(
			/* translators: %s: option name */
			sprintf( __( 'Option: %s', 'php2shell-guard' ), $option ),
			/* translators: %s: previous value */
			sprintf( __( 'Old value: %s', 'php2shell-guard' ), $old ),
			/* translators: %s: new value */
			sprintf( __( 'New value: %s', 'php2shell-guard' ), $new ),
		);
		$lines   = array_merge( $lines, self::context() );
		$lines[] = '';
		$lines[] = __( 'Changing the site URL or admin email is a common way to hijack a site or take over password resets.', 'php2shell-guard' );
		P2S_Alerts::event( $level, 'opt:' . $option, $title, $lines );
	}

	public static function on_upload( $file ) {
		$name = isset( $file['name'] ) ? (string) $file['name'] : '';
		if ( '' !== $name && preg_match( P2S_Scanner::EXT_ANY, $name ) ) {
			/* translators: %s: file name */
			$lines   = array( sprintf( __( 'File name: %s', 'php2shell-guard' ), sanitize_file_name( $name ) ) );
			$lines   = array_merge( $lines, self::context() );
			$lines[] = '';
			$lines[] = __( 'WordPress normally refuses these; an attempt to upload a PHP file is a typical web-shell drop.', 'php2shell-guard' );
			P2S_Alerts::event( 'critical', 'upload:' . $name . '|' . time(), __( 'PHP file upload attempt', 'php2shell-guard' ), $lines );
		}
		return $file;
	}

	/** Updates legitimately change theme functions.php, so refresh those entries. */
	public static function on_upgrade( $upgrader, $extra ) {
		if ( is_array( $extra ) && isset( $extra['type'] ) && in_array( $extra['type'], array( 'theme', 'plugin', 'core' ), true ) ) {
			$base = self::get_baseline();
			if ( $base ) {
				$snap = self::snapshot();
				foreach ( self::watched_files() as $path => $level ) {
					if ( 'review' !== $level ) {
						continue;
					}
					if ( isset( $snap[ $path ] ) ) {
						$base['files'][ $path ] = $snap[ $path ];
					} else {
						unset( $base['files'][ $path ] );
					}
				}
				update_option( self::BASELINE, $base, false );
			}
		}
	}

	public static function report_deactivation() {
		$lines   = array( __( 'PHP2Shell Guard was deactivated.', 'php2shell-guard' ) );
		$lines   = array_merge( $lines, self::context() );
		$lines[] = '';
		$lines[] = __( 'If you did not do this, an attacker may be switching off the guard.', 'php2shell-guard' );
		P2S_Alerts::event( 'critical', 'deactivated:' . time(), __( 'PHP2Shell Guard was deactivated', 'php2shell-guard' ), $lines );
	}

	/* ==================================================================
	 * Baseline and watcher
	 * ================================================================ */

	/**
	 * Files that should rarely change. Path => level.
	 */
	public static function watched_files() {
		$root   = untrailingslashit( wp_normalize_path( ABSPATH ) );
		$parent = dirname( $root );
		$list   = array(
			$root . '/wp-config.php'   => 'critical',
			$parent . '/wp-config.php' => 'critical',
			$root . '/index.php'       => 'critical',
			$root . '/.htaccess'       => 'critical',
			$root . '/.user.ini'       => 'critical',
			$root . '/php.ini'         => 'critical',
			$parent . '/.user.ini'     => 'critical',
			$parent . '/.htaccess'     => 'critical',
		);
		$mu = wp_normalize_path( WPMU_PLUGIN_DIR );
		if ( is_dir( $mu ) ) {
			foreach ( array_merge( (array) glob( $mu . '/*.php' ), (array) glob( $mu . '/*/*.php' ) ) as $f ) {
				$list[ wp_normalize_path( $f ) ] = 'critical';
			}
		}
		$list[ wp_normalize_path( get_stylesheet_directory() ) . '/functions.php' ] = 'review';
		$list[ wp_normalize_path( get_template_directory() ) . '/functions.php' ]   = 'review';
		return $list;
	}

	/** Path => sha1 of every watched file that exists. */
	public static function snapshot() {
		$snap = array();
		foreach ( self::watched_files() as $path => $level ) {
			if ( is_file( $path ) && is_readable( $path ) && filesize( $path ) < 5 * 1024 * 1024 ) {
				$snap[ $path ] = sha1_file( $path );
			}
		}
		return $snap;
	}

	public static function admin_ids() {
		$ids = get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) );
		return array_map( 'intval', $ids );
	}

	public static function get_baseline() {
		$b = get_option( self::BASELINE, false );
		return ( is_array( $b ) && ! empty( $b['time'] ) ) ? $b : false;
	}

	public static function accept_baseline() {
		update_option(
			self::BASELINE,
			array(
				'time'   => time(),
				'files'  => self::snapshot(),
				'admins' => self::admin_ids(),
			),
			false
		);
		self::forget_prefixes( array( 'file', 'admin' ) );
	}

	/**
	 * Runs every 15 minutes from WP-Cron.
	 */
	public static function watch() {
		@set_time_limit( 60 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

		self::watch_uploads();

		$base = self::get_baseline();
		if ( ! $base ) {
			return; // No trusted baseline yet; the first clean scan creates it.
		}

		// 1. Critical files.
		$now     = self::snapshot();
		$levels  = self::watched_files();
		$old     = isset( $base['files'] ) ? $base['files'] : array();
		$changes = array();
		foreach ( $now as $path => $hash ) {
			if ( ! isset( $old[ $path ] ) ) {
				$changes[] = array( $path, 'appeared', $hash );
			} elseif ( $old[ $path ] !== $hash ) {
				$changes[] = array( $path, 'modified', $hash );
			}
		}
		foreach ( $old as $path => $hash ) {
			if ( ! isset( $now[ $path ] ) && isset( $levels[ $path ] ) ) {
				$changes[] = array( $path, 'removed', '' );
			}
		}
		$root = untrailingslashit( wp_normalize_path( ABSPATH ) ) . '/';
		foreach ( $changes as $c ) {
			list( $path, $what, $hash ) = $c;
			if ( ! self::once( 'file:' . $path . '|' . $what . '|' . $hash ) ) {
				continue;
			}
			$level   = isset( $levels[ $path ] ) ? $levels[ $path ] : 'critical';
			$shown   = 0 === strpos( $path, $root ) ? substr( $path, strlen( $root ) ) : $path;
			$mt      = @filemtime( $path );
			$verbs   = array(
				/* translators: %s: file path */
				'appeared' => __( '%s appeared.', 'php2shell-guard' ),
				/* translators: %s: file path */
				'modified' => __( '%s was modified.', 'php2shell-guard' ),
				/* translators: %s: file path */
				'removed'  => __( '%s was removed.', 'php2shell-guard' ),
			);
			$lines   = array( sprintf( $verbs[ $what ], $shown ) );
			if ( $mt ) {
				/* translators: %s: date and time in UTC */
				$lines[] = sprintf( __( 'File time: %s UTC', 'php2shell-guard' ), gmdate( 'Y-m-d H:i:s', $mt ) );
			}
			$lines[] = '';
			$lines[] = __( 'If you made this change yourself, open the plugin page and click "Accept current state".', 'php2shell-guard' );
			/* translators: %s: file path */
			P2S_Alerts::event( $level, 'file:' . $path . '|' . $hash, sprintf( __( 'Critical file changed: %s', 'php2shell-guard' ), $shown ), $lines );
		}

		// 2. Administrators, including ones inserted straight into the database.
		$known = array_map( 'intval', isset( $base['admins'] ) ? (array) $base['admins'] : array() );
		foreach ( self::admin_ids() as $id ) {
			if ( ! in_array( $id, $known, true ) ) {
				self::admin_created( $id, __( 'found by the watcher; it may have bypassed WordPress', 'php2shell-guard' ) );
			}
		}
	}

	/** New PHP-like files in uploads since the last time we looked. */
	private static function watch_uploads() {
		$s   = new P2S_Scanner( 20 );
		$bad = $s->uploads_suspicious();
		if ( ! $bad ) {
			return;
		}
		$root = untrailingslashit( wp_normalize_path( ABSPATH ) ) . '/';
		foreach ( $bad as $b ) {
			if ( ! self::once( 'upfile:' . $b['path'] . '|' . $b['mtime'] ) ) {
				continue;
			}
			$shown   = 0 === strpos( $b['path'], $root ) ? substr( $b['path'], strlen( $root ) ) : $b['path'];
			$lines   = array(
				$shown,
				/* translators: 1: file size, 2: date and time in UTC */
				sprintf( __( 'Size: %1$s, modified %2$s UTC', 'php2shell-guard' ), size_format( $b['size'] ), gmdate( 'Y-m-d H:i:s', $b['mtime'] ) ),
				'php' === $b['why']
					? __( 'Why: an executable PHP file in the uploads folder', 'php2shell-guard' )
					: __( 'Why: a server config file in uploads that changes how files are executed', 'php2shell-guard' ),
				'',
				__( 'Inspect before deleting; the file is evidence of how the site was entered.', 'php2shell-guard' ),
			);
			P2S_Alerts::event( 'critical', 'upfile:' . $b['path'] . '|' . $b['mtime'], __( 'Suspicious file in uploads', 'php2shell-guard' ), $lines );
		}
	}
}
