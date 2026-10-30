<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Read-only compromise checks. Nothing in here modifies or deletes a file.
 *
 * Every check returns findings. A finding has a level:
 *   critical - very likely a problem; alerts are sent for these,
 *   review   - needs a human look; alerted only if the user opts in,
 *   ok / info - shown for context.
 */
class P2S_Scanner {

	const OPT      = 'p2s_results';
	const CHUNK    = 8;
	const EXT_END  = '~\.(php\d?|phtml|phar|pht)$~i';
	const EXT_ANY  = '~\.(php\d?|phtml|phar|pht|phps)(\.|$)~i';
	const CRASH_RE = '~SIGSEGV|SIGBUS|Segmentation fault|signal (7|11) \(|core dumped~';

	private $budget;
	private $deadline;
	private $root;
	private $cur       = '';
	private $truncated = false;

	/**
	 * @param int $budget Seconds each check may run before it stops early.
	 */
	public function __construct( $budget = 25 ) {
		$this->budget   = (int) $budget;
		$this->deadline = microtime( true ) + $this->budget;
		$this->root     = untrailingslashit( wp_normalize_path( ABSPATH ) );
	}

	/** Check id => label, in display order. */
	public static function checks() {
		return array(
			'php'             => __( 'PHP version', 'php2shell-guard' ),
			'upload_progress' => __( 'session.upload_progress (CVE-2026-115560 mitigation)', 'php2shell-guard' ),
			'core'            => __( 'WordPress core integrity', 'php2shell-guard' ),
			'plugins'         => __( 'Plugin integrity (wordpress.org plugins)', 'php2shell-guard' ),
			'uploads'         => __( 'Executable files in uploads', 'php2shell-guard' ),
			'files'           => __( 'Recently changed files and auto-prepend hooks', 'php2shell-guard' ),
			'mu'              => __( 'Must-use plugins', 'php2shell-guard' ),
			'patterns'        => __( 'Backdoor code patterns in wp-content', 'php2shell-guard' ),
			'users'           => __( 'Users', 'php2shell-guard' ),
			'database'        => __( 'Database', 'php2shell-guard' ),
			'cron'            => __( 'Scheduled events', 'php2shell-guard' ),
			'logs'            => __( 'Web server logs', 'php2shell-guard' ),
		);
	}

	/* ==================================================================
	 * Running and storing
	 * ================================================================ */

	public function run_check( $id, $offset = 0 ) {
		if ( ! isset( self::checks()[ $id ] ) ) {
			return $this->res( array() );
		}
		$this->cur       = $id;
		$this->truncated = false;
		$this->deadline  = microtime( true ) + $this->budget;

		try {
			$r = $this->{'check_' . $id}( (int) $offset );
		} catch ( Throwable $e ) {
			$r = $this->res(
				array(
					$this->f( 'review', 'check_failed', __( 'This check could not run', 'php2shell-guard' ), $e->getMessage() ),
				)
			);
		}
		if ( $this->truncated ) {
			$r['findings'][] = $this->f(
				'review',
				'truncated',
				__( 'Scan stopped early (time limit)', 'php2shell-guard' ),
				__( 'The check ran out of its time budget on a large site, so part of the file tree was not examined. Run it again, or raise max_execution_time.', 'php2shell-guard' )
			);
		}
		if ( null === $r['next'] ) {
			self::store( $id, $r['findings'] );
		}
		return $r;
	}

	/** Runs every check; used by WP-Cron. */
	public static function cron_run() {
		if ( get_transient( 'p2s_lock' ) ) {
			return;
		}
		set_transient( 'p2s_lock', 1, 20 * MINUTE_IN_SECONDS );
		@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		@ignore_user_abort( true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

		$s = new self( 240 );
		foreach ( array_keys( self::checks() ) as $id ) {
			$offset = 0;
			do {
				$r      = $s->run_check( $id, $offset );
				$offset = $r['next'];
			} while ( null !== $offset );
		}
		self::finish();
		delete_transient( 'p2s_lock' );
	}

	/** Called after the last check, from cron or from the admin page. */
	public static function finish() {
		$r              = self::results();
		$r['last_full'] = time();
		update_option( self::OPT, $r, false );

		// The baseline is only taken from a state that scanned clean.
		if ( ! P2S_Monitor::get_baseline() && ! self::open_findings( array( 'critical' ) ) ) {
			P2S_Monitor::accept_baseline();
		}
		P2S_Alerts::process_scan();
	}

	private static function store( $id, array $findings ) {
		$r = self::results();
		if ( ! isset( $r['checks'] ) || ! is_array( $r['checks'] ) ) {
			$r['checks'] = array();
		}
		$r['checks'][ $id ] = array(
			'time'     => time(),
			'findings' => $findings,
		);
		update_option( self::OPT, $r, false );
	}

	public static function results() {
		$r = get_option( self::OPT, array() );
		return is_array( $r ) ? $r : array();
	}

	/** Findings of the given levels that the user has not acknowledged. */
	public static function open_findings( array $levels ) {
		$r   = self::results();
		$ack = get_option( 'p2s_ack', array() );
		$ack = is_array( $ack ) ? $ack : array();
		$out = array();
		if ( empty( $r['checks'] ) ) {
			return $out;
		}
		foreach ( $r['checks'] as $c ) {
			foreach ( $c['findings'] as $f ) {
				if ( in_array( $f['level'], $levels, true ) && ! isset( $ack[ $f['fp'] ] ) ) {
					$out[] = $f;
				}
			}
		}
		return $out;
	}

	/* ==================================================================
	 * Small helpers
	 * ================================================================ */

	private function res( array $findings, $next = null ) {
		return array(
			'findings' => $findings,
			'next'     => $next,
		);
	}

	/**
	 * Builds a finding. $code is a stable, untranslated id so acknowledgements
	 * and "already alerted" markers survive a language change.
	 */
	private function f( $level, $code, $title, $detail = '', array $items = array() ) {
		$full = implode( "\n", $items );
		$more = 0;
		if ( count( $items ) > 200 ) {
			$more  = count( $items ) - 200;
			$items = array_slice( $items, 0, 200 );
		}
		return array(
			'check'  => $this->cur,
			'level'  => $level,
			'code'   => $code,
			'title'  => $title,
			'detail' => $detail,
			'items'  => $items,
			'more'   => $more,
			'fp'     => sha1( $this->cur . '|' . $code . '|' . $level . '|' . $full ),
		);
	}

	private function rel( $path ) {
		$path = wp_normalize_path( $path );
		return ( 0 === strpos( $path, $this->root . '/' ) ) ? substr( $path, strlen( $this->root ) + 1 ) : $path;
	}

	/**
	 * Walks files under $dir without following symlinked directories.
	 * Stops (and flags the scan as truncated) when the time budget is gone.
	 *
	 * @param callable $cb function ( string $normalized_path, SplFileInfo $file ).
	 */
	private function walk( $dir, array $skip_dirs, $cb ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		try {
			$it  = new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS );
			$flt = new RecursiveCallbackFilterIterator(
				$it,
				function ( $cur ) use ( $skip_dirs ) {
					if ( $cur->isDir() ) {
						return ! $cur->isLink() && ! in_array( $cur->getFilename(), $skip_dirs, true );
					}
					return true;
				}
			);
			$rii = new RecursiveIteratorIterator( $flt, RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD );
			foreach ( $rii as $file ) {
				if ( microtime( true ) > $this->deadline ) {
					$this->truncated = true;
					return;
				}
				if ( $file->isFile() && ! $file->isLink() ) {
					call_user_func( $cb, wp_normalize_path( $file->getPathname() ), $file );
				}
			}
		} catch ( Exception $e ) {
			return;
		}
	}

	/* ==================================================================
	 * PHP version
	 * ================================================================ */

	/** Fixed releases per branch. Filterable so it can be updated without a release. */
	public static function fixed_versions() {
		$fixed = array(
			'8.2' => '8.2.35',
			'8.3' => '8.3.36',
			'8.4' => '8.4.27',
			'8.5' => '8.5.12',
		);
		return function_exists( 'apply_filters' ) ? apply_filters( 'p2s_php_fixed_versions', $fixed ) : $fixed;
	}

	/**
	 * Judges a PHP version against the fixed releases.
	 *
	 * @return array{level:string,title:string,detail:string}
	 */
	public static function php_verdict( $version ) {
		if ( ! preg_match( '/^(\d+)\.(\d+)\.(\d+)/', $version, $m ) ) {
			return array(
				'level'  => 'review',
				'title'  => __( 'PHP version could not be parsed', 'php2shell-guard' ),
				'detail' => $version,
			);
		}
		$clean = $m[1] . '.' . $m[2] . '.' . $m[3];
		$mm    = $m[1] . '.' . $m[2];
		$fixed = self::fixed_versions();

		if ( isset( $fixed[ $mm ] ) ) {
			if ( version_compare( $clean, $fixed[ $mm ], '>=' ) ) {
				return array(
					'level'  => 'ok',
					'title'  => __( 'PHP is at or above the fixed release', 'php2shell-guard' ),
					/* translators: 1: running PHP version, 2: fixed version */
					'detail' => sprintf( __( 'Running PHP %1$s; the fixed release for this branch is %2$s.', 'php2shell-guard' ), $version, $fixed[ $mm ] ),
				);
			}
			return array(
				'level'  => 'critical',
				'title'  => __( 'PHP is below the fixed release', 'php2shell-guard' ),
				/* translators: 1: running PHP version, 2: fixed version */
				'detail' => sprintf( __( 'Running PHP %1$s; upgrade to %2$s or newer.', 'php2shell-guard' ), $version, $fixed[ $mm ] ),
			);
		}
		if ( version_compare( $mm . '.0', '8.6.0', '>=' ) ) {
			return array(
				'level'  => 'ok',
				'title'  => __( 'PHP is newer than the fixed branches', 'php2shell-guard' ),
				'detail' => sprintf( 'PHP %s', $version ),
			);
		}
		if ( in_array( $mm, array( '7.4', '8.0', '8.1' ), true ) ) {
			return array(
				'level'  => 'critical',
				'title'  => __( 'PHP is on an end-of-life branch', 'php2shell-guard' ),
				/* translators: %s: running PHP version */
				'detail' => sprintf( __( 'Running PHP %s. php.net shipped no release for this branch, but security-team backports exist via deb.sury.org, Remi and enterprise distributions. Check the package changelog for CVE-2026-109618 and CVE-2026-109619, and plan the move to 8.2 or newer. If your distribution has backported the fix, acknowledge this finding.', 'php2shell-guard' ), $version ),
			);
		}
		return array(
			'level'  => 'critical',
			'title'  => __( 'PHP is on an end-of-life branch with no fix', 'php2shell-guard' ),
			/* translators: %s: running PHP version */
			'detail' => sprintf( __( 'Running PHP %s. Move to 8.2 or newer.', 'php2shell-guard' ), $version ),
		);
	}

	private function check_php() {
		$v = self::php_verdict( PHP_VERSION );
		return $this->res(
			array(
				$this->f( $v['level'], 'php_version', $v['title'], $v['detail'] ),
				$this->f(
					'info',
					'php_note',
					__( 'About this result', 'php2shell-guard' ),
					sprintf(
						/* translators: %s: PHP SAPI name */
						__( 'This is the PHP that actually serves the website (SAPI: %s), not the command-line PHP. Distribution packages (Ubuntu, Debian, RHEL) may backport the fix without changing the version number; check the package changelog for the CVE IDs. CVE-2026-115560 is not covered by the October releases.', 'php2shell-guard' ),
						PHP_SAPI
					)
				),
			)
		);
	}

	/* ==================================================================
	 * session.upload_progress
	 * ================================================================ */

	public static function ini_is_on( $value ) {
		if ( false === $value ) {
			return false;
		}
		return ! in_array( strtolower( trim( (string) $value ) ), array( '', '0', 'off', 'false', 'no', 'none' ), true );
	}

	private function check_upload_progress() {
		$raw = ini_get( 'session.upload_progress.enabled' );
		if ( false === $raw ) {
			return $this->res( array( $this->f( 'ok', 'up_none', __( 'The session extension is not loaded', 'php2shell-guard' ), __( 'The setting does not exist on this PHP build, so there is nothing to mitigate.', 'php2shell-guard' ) ) ) );
		}
		if ( ! self::ini_is_on( $raw ) ) {
			return $this->res( array( $this->f( 'ok', 'up_off', __( 'session.upload_progress.enabled is Off', 'php2shell-guard' ), __( 'The CVE-2026-115560 mitigation is in place for the PHP serving this site.', 'php2shell-guard' ) ) ) );
		}
		return $this->res(
			array(
				$this->f(
					'review',
					'up_on',
					__( 'session.upload_progress.enabled is still On', 'php2shell-guard' ),
					__( 'php.net asks for session.upload_progress.enabled=0 in php.ini or the PHP-FPM pool, followed by a restart, until the CVE-2026-115560 fix ships in the next regular release. ini_set() and .user.ini do not work for this setting. The bug only bites when an application switches session.serialize_handler at runtime, which WordPress never does, so this is housekeeping rather than a sign of compromise.', 'php2shell-guard' )
				),
			)
		);
	}

	/* ==================================================================
	 * Core integrity
	 * ================================================================ */

	private function check_core() {
		global $wp_version;
		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		$locale = function_exists( 'get_locale' ) ? get_locale() : 'en_US';
		$cs     = get_core_checksums( $wp_version, $locale );
		if ( ! is_array( $cs ) ) {
			return $this->res(
				array(
					$this->f(
						'review',
						'core_skipped',
						__( 'Core integrity was not checked', 'php2shell-guard' ),
						sprintf(
							/* translators: 1: WordPress version, 2: locale */
							__( 'Could not get checksums from api.wordpress.org for %1$s (%2$s). Beta versions and blocked outbound requests cause this.', 'php2shell-guard' ),
							$wp_version,
							$locale
						)
					),
				)
			);
		}

		$ignore  = array( 'readme.html', 'license.txt', 'wp-config-sample.php' );
		$mod     = array();
		$missing = array();
		foreach ( $cs as $rel => $md5 ) {
			if ( 0 === strpos( $rel, 'wp-content/' ) || in_array( $rel, $ignore, true ) ) {
				continue;
			}
			$path = $this->root . '/' . $rel;
			if ( ! is_file( $path ) ) {
				if ( preg_match( self::EXT_END, $rel ) ) {
					$missing[] = $rel;
				}
				continue;
			}
			if ( md5_file( $path ) !== $md5 ) {
				$mod[] = $rel;
			}
		}

		$extra = array();
		foreach ( array( 'wp-admin', 'wp-includes' ) as $d ) {
			$this->walk(
				$this->root . '/' . $d,
				array(),
				function ( $p ) use ( $cs, &$extra ) {
					$rel = $this->rel( $p );
					if ( ! isset( $cs[ $rel ] ) && ! preg_match( '~(^|/)error_log$|\.log$~', $rel ) ) {
						$extra[] = $rel;
					}
				}
			);
		}

		$root_extra = array();
		foreach ( (array) glob( $this->root . '/*.php' ) as $p ) {
			$rel = basename( $p );
			if ( ! isset( $cs[ $rel ] ) && 'wp-config.php' !== $rel ) {
				$root_extra[] = $rel;
			}
		}

		$out = array();
		if ( $mod ) {
			sort( $mod );
			$out[] = $this->f( 'critical', 'core_modified', __( 'WordPress core files were modified', 'php2shell-guard' ), sprintf( __( '%d file(s) differ from the official wordpress.org release.', 'php2shell-guard' ), count( $mod ) ), $mod );
		}
		if ( $extra ) {
			sort( $extra );
			$out[] = $this->f( 'critical', 'core_extra', __( 'Unknown files inside wp-admin or wp-includes', 'php2shell-guard' ), sprintf( __( '%d file(s) do not belong to WordPress. This is often a dropped shell.', 'php2shell-guard' ), count( $extra ) ), $extra );
		}
		if ( $missing ) {
			sort( $missing );
			$out[] = $this->f( 'review', 'core_missing', __( 'Core PHP files are missing', 'php2shell-guard' ), __( 'Reinstall core from Dashboard, Updates, Re-install.', 'php2shell-guard' ), $missing );
		}
		if ( $root_extra ) {
			sort( $root_extra );
			$out[] = $this->f( 'review', 'core_root_extra', __( 'Extra PHP files in the site root', 'php2shell-guard' ), __( 'A custom script at the site root is the usual benign cause; check each one.', 'php2shell-guard' ), $root_extra );
		}
		if ( ! $mod && ! $extra ) {
			$out[] = $this->f( 'ok', 'core_ok', __( 'Core files match wordpress.org checksums', 'php2shell-guard' ), __( 'No modified files and no extra files in wp-admin or wp-includes.', 'php2shell-guard' ) );
		}
		return $this->res( $out );
	}

	/* ==================================================================
	 * Plugin integrity
	 * ================================================================ */

	private function check_plugins( $offset = 0 ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$list = array();
		foreach ( get_plugins() as $file => $data ) {
			if ( false === strpos( $file, '/' ) ) {
				continue; // Single-file plugins cannot be verified.
			}
			$list[] = array( dirname( $file ), (string) $data['Version'] );
		}
		$total = count( $list );

		$state = ( 0 === $offset ) ? false : get_transient( 'p2s_pstate' );
		if ( ! is_array( $state ) ) {
			$state = array( 'bad' => array(), 'none' => array(), 'err' => array(), 'ok' => 0 );
		}

		foreach ( array_slice( $list, $offset, self::CHUNK ) as $p ) {
			list( $slug, $ver ) = $p;
			$v = $this->verify_plugin( $slug, $ver );
			if ( 'ok' === $v['status'] ) {
				$state['ok']++;
			} elseif ( 'bad' === $v['status'] ) {
				$state['bad'] = array_merge( $state['bad'], $v['bad'] );
			} elseif ( 'none' === $v['status'] ) {
				$state['none'][] = $slug;
			} else {
				$state['err'][] = $slug;
			}
		}

		$next = ( $offset + self::CHUNK < $total ) ? $offset + self::CHUNK : null;
		if ( null !== $next ) {
			set_transient( 'p2s_pstate', $state, HOUR_IN_SECONDS );
			return $this->res( array(), $next );
		}
		delete_transient( 'p2s_pstate' );

		$out = array();
		if ( $state['bad'] ) {
			sort( $state['bad'] );
			$out[] = $this->f( 'critical', 'plugins_modified', __( 'Plugin files differ from wordpress.org', 'php2shell-guard' ), sprintf( __( '%d file(s) were modified, added or removed compared with the published release.', 'php2shell-guard' ), count( $state['bad'] ) ), $state['bad'] );
		}
		if ( $state['err'] ) {
			$out[] = $this->f( 'review', 'plugins_unreachable', __( 'Some plugins could not be verified', 'php2shell-guard' ), __( 'The checksum request failed (network or wordpress.org unavailable). Try again later.', 'php2shell-guard' ), $state['err'] );
		}
		if ( $state['none'] ) {
			sort( $state['none'] );
			$out[] = $this->f( 'info', 'plugins_unverifiable', __( 'Not verifiable (premium or custom plugins)', 'php2shell-guard' ), __( 'Compare these against a fresh download or your repository.', 'php2shell-guard' ), $state['none'] );
		}
		if ( ! $state['bad'] && $state['ok'] > 0 ) {
			$out[] = $this->f( 'ok', 'plugins_ok', __( 'Verified plugins match wordpress.org checksums', 'php2shell-guard' ), sprintf( __( '%d plugin(s) verified.', 'php2shell-guard' ), $state['ok'] ) );
		}
		if ( ! $out ) {
			$out[] = $this->f( 'info', 'plugins_none', __( 'No plugins to verify', 'php2shell-guard' ) );
		}
		return $this->res( $out );
	}

	private function verify_plugin( $slug, $version ) {
		$cs = $this->plugin_checksums( $slug, $version );
		if ( null === $cs ) {
			return array( 'status' => 'err' );
		}
		if ( false === $cs ) {
			return array( 'status' => 'none' );
		}
		$dir = wp_normalize_path( WP_PLUGIN_DIR . '/' . $slug );
		$bad = array();
		foreach ( $cs as $rel => $hashes ) {
			$path = $dir . '/' . $rel;
			if ( ! is_file( $path ) ) {
				if ( preg_match( self::EXT_END, $rel ) ) {
					$bad[] = $slug . '/' . $rel . ' (missing)';
				}
				continue;
			}
			if ( ! self::hash_matches( $path, $hashes ) ) {
				$bad[] = $slug . '/' . $rel . ' (modified)';
			}
		}
		$this->walk(
			$dir,
			array( 'node_modules' ),
			function ( $p ) use ( $dir, $cs, $slug, &$bad ) {
				$rel = ltrim( substr( $p, strlen( $dir ) ), '/' );
				if ( preg_match( self::EXT_ANY, $rel ) && ! isset( $cs[ $rel ] ) ) {
					$bad[] = $slug . '/' . $rel . ' (added)';
				}
			}
		);
		return $bad ? array( 'status' => 'bad', 'bad' => $bad ) : array( 'status' => 'ok' );
	}

	/** @param array|string $hashes e.g. ['md5'=>..., 'sha256'=>...]. */
	private static function hash_matches( $path, $hashes ) {
		if ( ! is_array( $hashes ) ) {
			return true;
		}
		foreach ( array( 'sha256', 'md5' ) as $algo ) {
			if ( ! empty( $hashes[ $algo ] ) ) {
				$want = (array) $hashes[ $algo ];
				return in_array( hash_file( $algo, $path ), $want, true );
			}
		}
		return true;
	}

	/**
	 * @return array|false|null files map; false = not a wordpress.org plugin; null = request failed.
	 */
	private function plugin_checksums( $slug, $version ) {
		$key = 'p2s_pc_' . md5( $slug . '|' . $version );
		$c   = get_transient( $key );
		if ( is_array( $c ) && array_key_exists( 'files', $c ) ) {
			return $c['files'];
		}
		$url  = 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json';
		$resp = wp_remote_get( $url, array( 'timeout' => 15 ) );
		if ( is_wp_error( $resp ) ) {
			return null;
		}
		$code = (int) wp_remote_retrieve_response_code( $resp );
		if ( 404 === $code ) {
			set_transient( $key, array( 'files' => false ), 12 * HOUR_IN_SECONDS );
			return false;
		}
		if ( 200 !== $code ) {
			return null;
		}
		$j = json_decode( wp_remote_retrieve_body( $resp ), true );
		if ( ! is_array( $j ) || empty( $j['files'] ) || ! is_array( $j['files'] ) ) {
			return null;
		}
		set_transient( $key, array( 'files' => $j['files'] ), 12 * HOUR_IN_SECONDS );
		return $j['files'];
	}

	/* ==================================================================
	 * Executable files in uploads
	 * ================================================================ */

	/**
	 * PHP-like files (and handler-changing .htaccess/.user.ini) inside uploads.
	 * Empty files and "Silence is golden" stubs are ignored.
	 *
	 * @return array|null null if there is no uploads directory.
	 */
	public function uploads_suspicious() {
		$up   = wp_get_upload_dir();
		$base = isset( $up['basedir'] ) ? wp_normalize_path( $up['basedir'] ) : '';
		if ( '' === $base || ! is_dir( $base ) ) {
			return null;
		}
		$out = array();
		$this->walk(
			$base,
			array(),
			function ( $p ) use ( &$out ) {
				$name = basename( $p );
				if ( preg_match( self::EXT_ANY, $name ) ) {
					$size = (int) @filesize( $p );
					if ( 0 === $size ) {
						return;
					}
					if ( $size < 200 ) {
						$c = @file_get_contents( $p );
						if ( false !== $c && false !== stripos( $c, 'silence' ) ) {
							return;
						}
					}
					$out[] = array( 'path' => $p, 'mtime' => (int) @filemtime( $p ), 'size' => $size, 'why' => 'php' );
				} elseif ( in_array( strtolower( $name ), array( '.htaccess', '.user.ini' ), true ) ) {
					$c = @file_get_contents( $p, false, null, 0, 65536 );
					if ( false !== $c && preg_match( '/AddHandler|AddType|SetHandler|php_value|php_flag|auto_(prepend|append)_file/i', $c ) ) {
						$out[] = array( 'path' => $p, 'mtime' => (int) @filemtime( $p ), 'size' => (int) @filesize( $p ), 'why' => 'config' );
					}
				}
			}
		);
		return $out;
	}

	private function check_uploads() {
		$bad = $this->uploads_suspicious();
		if ( null === $bad ) {
			return $this->res( array( $this->f( 'info', 'uploads_none', __( 'No uploads directory found', 'php2shell-guard' ) ) ) );
		}
		if ( ! $bad ) {
			return $this->res( array( $this->f( 'ok', 'uploads_ok', __( 'No executable PHP in uploads', 'php2shell-guard' ) ) ) );
		}
		$php = array();
		$cfg = array();
		foreach ( $bad as $b ) {
			$line = $this->rel( $b['path'] ) . ' (' . size_format( $b['size'] ) . ', ' . gmdate( 'Y-m-d H:i', $b['mtime'] ) . ' UTC)';
			if ( 'php' === $b['why'] ) {
				$php[ $this->rel( $b['path'] ) ] = $line;
			} else {
				$cfg[ $this->rel( $b['path'] ) ] = $line;
			}
		}
		ksort( $php );
		ksort( $cfg );
		$out = array();
		if ( $php ) {
			$out[] = $this->f( 'critical', 'uploads_php', __( 'PHP files in the uploads folder', 'php2shell-guard' ), sprintf( __( '%d file(s). Almost always malicious; inspect before deleting.', 'php2shell-guard' ), count( $php ) ), array_keys( $php ) );
			$out[ count( $out ) - 1 ]['items'] = array_values( $php );
		}
		if ( $cfg ) {
			$out[] = $this->f( 'critical', 'uploads_cfg', __( '.htaccess or .user.ini in uploads that changes how files are executed', 'php2shell-guard' ), __( 'WordPress never writes these there; attackers use them to make other file types run as PHP.', 'php2shell-guard' ), array_keys( $cfg ) );
			$out[ count( $out ) - 1 ]['items'] = array_values( $cfg );
		}
		return $this->res( $out );
	}

	/* ==================================================================
	 * Recently changed files + auto-prepend
	 * ================================================================ */

	/**
	 * Is this file shaped exactly like a WordPress translation pack
	 * (wp-includes/l10n/class-wp-translation-file-php.php writes
	 * "<?php" then one "return [...];" line)? With the string literals
	 * removed, the second line may hold only brackets, arrows, commas and
	 * integers, so no code can hide in it.
	 */
	public static function is_wp_l10n( $path ) {
		$c = @file_get_contents( $path, false, null, 0, 2 * 1024 * 1024 + 1 );
		if ( false === $c || strlen( $c ) > 2 * 1024 * 1024 ) {
			return false;
		}
		$lines = explode( "\n", rtrim( $c, "\n" ) );
		if ( count( $lines ) > 2 || ! isset( $lines[1] ) || '<?php' !== rtrim( $lines[0], "\r" ) ) {
			return false;
		}
		$l2 = preg_replace( "/'(\\\\.|[^'\\\\])*'/s", '', rtrim( $lines[1], "\r" ) );
		if ( ! is_string( $l2 ) ) {
			return false;
		}
		return (bool) preg_match( '/^return \[[\]\[>,=0-9]*\];$/', $l2 );
	}

	private function check_files() {
		$since    = (string) P2S_Settings::get( 'since' );
		$since_ts = (int) strtotime( $since . ' 00:00:00' );
		$cfgnames = array( '.htaccess', '.user.ini', 'php.ini' );
		$recent   = array();
		$l10n     = 0;
		$fake     = array();
		$prepend  = array();

		$this->walk(
			$this->root,
			array( 'cache', 'node_modules', '.git' ),
			function ( $p ) use ( $cfgnames, $since_ts, &$recent, &$l10n, &$fake, &$prepend ) {
				$name   = basename( $p );
				$is_cfg = in_array( $name, $cfgnames, true );
				if ( ! $is_cfg && ! preg_match( self::EXT_END, $name ) && ! preg_match( '~\.ico$~i', $name ) ) {
					return;
				}
				if ( $is_cfg ) {
					$c = @file_get_contents( $p, false, null, 0, 262144 );
					if ( false !== $c && preg_match( '/^[ \t]*[^#;\r\n]*auto_(prepend|append)_file[^\r\n]*/mi', $c, $m ) ) {
						$prepend[] = $this->rel( $p ) . ': ' . trim( $m[0] );
					}
				}
				$mt = @filemtime( $p );
				if ( false === $mt || $mt < $since_ts ) {
					return;
				}
				// WordPress rewrites translation packs on most update nights.
				if ( false !== strpos( $p, '/wp-content/languages/' ) && preg_match( '~\.l10n\.php$~', $p ) ) {
					if ( self::is_wp_l10n( $p ) ) {
						$l10n++;
						return;
					}
					$fake[] = $this->rel( $p );
				}
				$recent[ $this->rel( $p ) ] = $mt;
			}
		);
		// The parent folder's own config files (shared hosting layouts).
		foreach ( $cfgnames as $n ) {
			$p = dirname( $this->root ) . '/' . $n;
			if ( is_readable( $p ) && is_file( $p ) ) {
				$c = @file_get_contents( $p, false, null, 0, 262144 );
				if ( false !== $c && preg_match( '/^[ \t]*[^#;\r\n]*auto_(prepend|append)_file[^\r\n]*/mi', $c, $m ) ) {
					$prepend[] = '../' . $n . ': ' . trim( $m[0] );
				}
			}
		}

		$out = array();

		// Runtime view: what PHP itself has configured for this request.
		foreach ( array( 'auto_prepend_file', 'auto_append_file' ) as $dir ) {
			$val = (string) ini_get( $dir );
			if ( '' !== $val ) {
				$prepend[] = 'php.ini (runtime): ' . $dir . ' = ' . $val;
			}
		}
		if ( $prepend ) {
			$legit = true;
			foreach ( $prepend as $line ) {
				if ( false === strpos( $line, 'wordfence-waf.php' ) ) {
					$legit = false;
				}
			}
			$out[] = $this->f(
				$legit ? 'review' : 'critical',
				'autoprepend',
				__( 'auto_prepend_file / auto_append_file is set', 'php2shell-guard' ),
				$legit ? __( 'This looks like the Wordfence firewall loader, which is legitimate.', 'php2shell-guard' ) : __( 'Legitimate for Wordfence (wordfence-waf.php); anything else is a red flag because the file runs before every request.', 'php2shell-guard' ),
				array_values( array_unique( $prepend ) )
			);
		} else {
			$out[] = $this->f( 'ok', 'autoprepend_ok', __( 'No auto_prepend / auto_append directives', 'php2shell-guard' ) );
		}

		if ( $fake ) {
			$out[] = $this->f( 'critical', 'fake_l10n', __( 'Files named *.l10n.php that are not translation files', 'php2shell-guard' ), __( 'WordPress writes these as a single "return [...]" statement; these do not look like that. Inspect them.', 'php2shell-guard' ), $fake );
		}

		arsort( $recent );
		$count = count( $recent );
		if ( $count > 100 ) {
			$groups = array();
			foreach ( $recent as $rel => $mt ) {
				$parts = explode( '/', $rel );
				$d     = $parts[0];
				for ( $i = 1; $i < count( $parts ) - 1 && $i < 3; $i++ ) {
					$d .= '/' . $parts[ $i ];
				}
				if ( ! isset( $groups[ $d ] ) ) {
					$groups[ $d ] = array( 0, 0 );
				}
				$groups[ $d ][0]++;
				$groups[ $d ][1] = max( $groups[ $d ][1], $mt );
			}
			uasort(
				$groups,
				function ( $a, $b ) {
					return $b[0] - $a[0];
				}
			);
			$items = array();
			foreach ( $groups as $d => $g ) {
				$items[] = sprintf( '%5d  %s  %s/', $g[0], gmdate( 'Y-m-d H:i', $g[1] ), $d );
			}
			$out[] = $this->f( 'review', 'recent_many', __( 'Many PHP/config files changed in the window', 'php2shell-guard' ), sprintf( __( '%1$d file(s) changed since %2$s. Expected if you updated plugins or core since then; anything else needs a look. By directory: count, newest change, directory.', 'php2shell-guard' ), $count, $since ), $items );
		} elseif ( $count > 0 ) {
			$items = array();
			foreach ( $recent as $rel => $mt ) {
				$items[] = gmdate( 'Y-m-d H:i', $mt ) . '  ' . $rel;
			}
			$out[] = $this->f( 'review', 'recent', __( 'PHP/config files changed in the window', 'php2shell-guard' ), sprintf( __( '%1$d file(s) changed since %2$s. Expected if you updated plugins or core since then; anything else needs a look.', 'php2shell-guard' ), $count, $since ), $items );
		} else {
			$out[] = $this->f( 'ok', 'recent_ok', __( 'No PHP/config files modified in the window', 'php2shell-guard' ), sprintf( __( 'Since %s. Attackers can fake timestamps, so the checksum checks are the stronger test.', 'php2shell-guard' ), $since ) );
		}
		if ( $l10n > 0 ) {
			$out[] = $this->f( 'info', 'l10n_count', __( 'Translation files changed', 'php2shell-guard' ), sprintf( __( '%d *.l10n.php file(s) under wp-content/languages changed. WordPress rewrites these when language packs update, so they are not listed. They are still covered by the code-pattern scan.', 'php2shell-guard' ), $l10n ) );
		}
		return $this->res( $out );
	}

	/* ==================================================================
	 * Must-use plugins
	 * ================================================================ */

	private function check_mu() {
		$dir   = wp_normalize_path( WPMU_PLUGIN_DIR );
		$items = array();
		if ( is_dir( $dir ) ) {
			foreach ( (array) glob( $dir . '/*' ) as $p ) {
				$items[] = basename( $p ) . ( is_dir( $p ) ? '/' : ' (' . size_format( (int) @filesize( $p ) ) . ', ' . gmdate( 'Y-m-d H:i', (int) @filemtime( $p ) ) . ' UTC)' );
			}
		}
		if ( $items ) {
			return $this->res( array( $this->f( 'review', 'mu_present', __( 'Must-use plugins are present', 'php2shell-guard' ), __( 'They run on every request and do not appear in the normal plugin list. Confirm each one is yours. Changes to this folder are watched in real time.', 'php2shell-guard' ), $items ) ) );
		}
		return $this->res( array( $this->f( 'ok', 'mu_ok', __( 'No must-use plugins', 'php2shell-guard' ) ) ) );
	}

	/* ==================================================================
	 * Code patterns
	 * ================================================================ */

	private function check_patterns() {
		$re       = '~eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(POST|GET|REQUEST|COOKIE))|assert\s*\(\s*\$_(POST|GET|REQUEST)|\$_(POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(|preg_replace\s*\(\s*["\'].*/e["\']|create_function\s*\(.*\$_~i';
		$self     = wp_normalize_path( untrailingslashit( P2S_DIR ) ) . '/';
		$hits     = array();
		$skipped  = 0;
		$this->walk(
			wp_normalize_path( WP_CONTENT_DIR ),
			array( 'node_modules', '.git' ),
			function ( $p ) use ( $re, $self, &$hits, &$skipped ) {
				if ( 0 === strpos( $p, $self ) || ! preg_match( self::EXT_END, $p ) ) {
					return; // Skip this plugin's own pattern strings.
				}
				if ( (int) @filesize( $p ) > 1572864 ) {
					$skipped++;
					return;
				}
				$c = @file_get_contents( $p );
				if ( false !== $c && preg_match( $re, $c ) ) {
					$hits[] = $this->rel( $p );
				}
			}
		);
		$out = array();
		if ( $hits ) {
			sort( $hits );
			$out[] = $this->f( 'review', 'patterns', __( 'Files with classic web-shell patterns', 'php2shell-guard' ), __( 'Some obfuscated premium plugins trip this too, so confirm by reading the file.', 'php2shell-guard' ), array_slice( $hits, 0, 200 ) );
		} else {
			$out[] = $this->f( 'ok', 'patterns_ok', __( 'No classic web-shell patterns found', 'php2shell-guard' ) );
		}
		if ( $skipped ) {
			$out[] = $this->f( 'info', 'patterns_big', __( 'Large files skipped', 'php2shell-guard' ), sprintf( __( '%d PHP file(s) over 1.5 MB were not scanned.', 'php2shell-guard' ), $skipped ) );
		}
		return $this->res( $out );
	}

	/* ==================================================================
	 * Users
	 * ================================================================ */

	private function check_users() {
		global $wpdb;
		$since = (string) P2S_Settings::get( 'since' );
		$out   = array();

		$admins = get_users(
			array(
				'role'   => 'administrator',
				'fields' => array( 'ID', 'user_login', 'user_email', 'user_registered' ),
			)
		);
		$items  = array();
		$ids    = array();
		foreach ( $admins as $u ) {
			$ids[]   = (int) $u->ID;
			$items[] = '#' . $u->ID . '  ' . $u->user_login . '  ' . $u->user_email . '  (registered ' . $u->user_registered . ')';
		}
		$out[] = $this->f( 'info', 'admins', __( 'Administrators', 'php2shell-guard' ), __( 'Confirm every one is expected.', 'php2shell-guard' ), $items );

		$base = P2S_Monitor::get_baseline();
		if ( $base && isset( $base['admins'] ) ) {
			$new = array_diff( $ids, array_map( 'intval', (array) $base['admins'] ) );
			if ( $new ) {
				$lines = array();
				foreach ( $admins as $u ) {
					if ( in_array( (int) $u->ID, $new, true ) ) {
						$lines[] = '#' . $u->ID . '  ' . $u->user_login . '  ' . $u->user_email;
					}
				}
				$out[] = $this->f( 'critical', 'new_admins', __( 'Administrator accounts that did not exist at the baseline', 'php2shell-guard' ), __( 'If you created these yourself, use "Accept current state" on the Status tab.', 'php2shell-guard' ), $lines );
			}
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$recent = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, user_login, user_email, user_registered FROM {$wpdb->users} WHERE user_registered >= %s ORDER BY user_registered DESC LIMIT 100",
				$since . ' 00:00:00'
			)
		);
		if ( $recent ) {
			$lines = array();
			foreach ( $recent as $u ) {
				$ud      = get_userdata( (int) $u->ID );
				$lines[] = '#' . $u->ID . '  ' . $u->user_login . '  ' . $u->user_email . '  [' . ( $ud ? implode( ',', $ud->roles ) : '?' ) . ']  ' . $u->user_registered;
			}
			$out[] = $this->f( 'review', 'recent_users', __( 'Accounts registered in the window', 'php2shell-guard' ), sprintf( __( 'Since %s.', 'php2shell-guard' ), $since ), $lines );
		} else {
			$out[] = $this->f( 'ok', 'recent_users_ok', __( 'No accounts registered in the window', 'php2shell-guard' ), sprintf( __( 'Since %s.', 'php2shell-guard' ), $since ) );
		}
		return $this->res( $out );
	}

	/* ==================================================================
	 * Database
	 * ================================================================ */

	private function check_database() {
		global $wpdb;
		$out     = array();
		$siteurl = (string) get_option( 'siteurl' );
		$home    = (string) get_option( 'home' );
		$out[]   = $this->f( 'info', 'urls', __( 'Site URLs', 'php2shell-guard' ), __( 'Both should be your own domain.', 'php2shell-guard' ), array( 'siteurl: ' . $siteurl, 'home: ' . $home ) );
		if ( wp_parse_args( wp_parse_url( $siteurl ), array( 'host' => '' ) )['host'] !== wp_parse_args( wp_parse_url( $home ), array( 'host' => '' ) )['host'] ) {
			$out[] = $this->f( 'review', 'url_mismatch', __( 'siteurl and home are on different hosts', 'php2shell-guard' ), __( 'Legitimate in some setups (WordPress in its own folder or subdomain), but also a common redirect hijack.', 'php2shell-guard' ), array( $siteurl, $home ) );
		}

		$old = $wpdb->suppress_errors( true );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL
		$opts = $wpdb->get_results(
			"SELECT option_name, autoload, LENGTH(option_value) AS bytes FROM {$wpdb->options} WHERE option_name NOT LIKE 'p2s\\_%' AND option_value REGEXP 'eval[(]|base64_decode[(]|gzinflate[(]|String[.]fromCharCode|<script[^>]+src=' ORDER BY bytes DESC LIMIT 50",
			ARRAY_N
		);
		$err1 = $wpdb->last_error;
		$posts = $wpdb->get_results(
			"SELECT ID, post_type, post_status, post_modified FROM {$wpdb->posts} WHERE post_content REGEXP 'eval[(]|base64_decode[(]|String[.]fromCharCode|<script[^>]+src=' AND post_type <> 'revision' ORDER BY post_modified DESC LIMIT 50",
			ARRAY_N
		);
		$err2 = $wpdb->last_error;
		// phpcs:enable
		$wpdb->suppress_errors( $old );

		if ( '' !== $err1 ) {
			$out[] = $this->f( 'review', 'opts_skipped', __( 'The options scan failed', 'php2shell-guard' ), __( 'Large sites can hit MySQL regex limits, so options were not checked.', 'php2shell-guard' ), array( $err1 ) );
		} elseif ( $opts ) {
			$items = array();
			foreach ( $opts as $r ) {
				$items[] = $r[0] . '  (autoload ' . $r[1] . ', ' . $r[2] . ' bytes)';
			}
			$out[] = $this->f( 'review', 'opts_hits', __( 'Options containing script tags or obfuscation functions', 'php2shell-guard' ), __( 'Analytics and header-script plugins are legitimate hits.', 'php2shell-guard' ), $items );
		} else {
			$out[] = $this->f( 'ok', 'opts_ok', __( 'No suspicious content in options', 'php2shell-guard' ) );
		}

		if ( '' !== $err2 ) {
			$out[] = $this->f( 'review', 'posts_skipped', __( 'The posts scan failed', 'php2shell-guard' ), __( 'Large sites can hit MySQL regex limits, so post content was not checked.', 'php2shell-guard' ), array( $err2 ) );
		} elseif ( $posts ) {
			$items = array();
			foreach ( $posts as $r ) {
				$items[] = '#' . $r[0] . '  ' . $r[1] . '  ' . $r[2] . '  ' . $r[3];
			}
			$out[] = $this->f( 'review', 'posts_hits', __( 'Posts or pages with external scripts or obfuscation', 'php2shell-guard' ), __( 'Embeds can be legitimate.', 'php2shell-guard' ), $items );
		} else {
			$out[] = $this->f( 'ok', 'posts_ok', __( 'No suspicious scripts in post content', 'php2shell-guard' ) );
		}
		return $this->res( $out );
	}

	/* ==================================================================
	 * Cron
	 * ================================================================ */

	private function check_cron() {
		$cron  = _get_cron_array();
		$items = array();
		$total = 0;
		if ( is_array( $cron ) ) {
			foreach ( $cron as $ts => $hooks ) {
				if ( ! is_array( $hooks ) ) {
					continue;
				}
				foreach ( $hooks as $hook => $events ) {
					$total += count( $events );
					if ( ! has_action( $hook ) ) {
						$items[ $hook ] = $hook . '  (next ' . gmdate( 'Y-m-d H:i', (int) $ts ) . ' UTC)';
					}
				}
			}
		}
		if ( $items ) {
			ksort( $items );
			return $this->res( array( $this->f( 'review', 'cron_orphans', __( 'Scheduled events with no code attached', 'php2shell-guard' ), __( 'Usually left behind by a removed plugin; sometimes a persistence trick. Hooks that only register on certain pages can show up here too.', 'php2shell-guard' ), array_values( $items ) ) ) );
		}
		return $this->res( array( $this->f( 'ok', 'cron_ok', __( 'Every scheduled event has code attached', 'php2shell-guard' ), sprintf( __( '%d event(s) examined.', 'php2shell-guard' ), $total ) ) ) );
	}

	/* ==================================================================
	 * Logs
	 * ================================================================ */

	/** Parses a common/combined-format access log line. */
	public static function parse_access_line( $line ) {
		static $mon = array(
			'Jan' => '01', 'Feb' => '02', 'Mar' => '03', 'Apr' => '04', 'May' => '05', 'Jun' => '06',
			'Jul' => '07', 'Aug' => '08', 'Sep' => '09', 'Oct' => '10', 'Nov' => '11', 'Dec' => '12',
		);
		if ( ! preg_match( '~\[(\d{2})/([A-Z][a-z]{2})/(\d{4}):[^\]]*\]\s+"([A-Z]+)\s+(\S+)[^"]*"\s+(\d{3})\s~', $line, $m ) || ! isset( $mon[ $m[2] ] ) ) {
			return null;
		}
		$path = $m[5];
		$q    = strpos( $path, '?' );
		if ( false !== $q ) {
			$path = substr( $path, 0, $q );
		}
		return array(
			'day'    => $m[3] . '-' . $mon[ $m[2] ] . '-' . $m[1],
			'status' => (int) $m[6],
			'path'   => $path,
		);
	}

	private function log_files() {
		$patterns = array();
		$custom   = trim( (string) P2S_Settings::get( 'log_paths' ) );
		if ( '' !== $custom ) {
			$patterns = array_filter( array_map( 'trim', preg_split( '/\R/', $custom ) ) );
		} else {
			$home     = (string) getenv( 'HOME' );
			$patterns = array(
				dirname( $this->root ) . '/logs/*',
				dirname( $this->root ) . '/log/*',
				$home . '/logs/*',
				'/var/log/apache2/*',
				'/var/log/httpd/*',
				'/var/log/nginx/*',
				'/var/log/php*fpm*.log*',
				'/var/log/php-fpm/*',
				wp_normalize_path( WP_CONTENT_DIR ) . '/debug.log',
				(string) ini_get( 'error_log' ),
			);
		}
		$files = array();
		foreach ( $patterns as $pat ) {
			if ( '' === $pat ) {
				continue;
			}
			foreach ( (array) @glob( $pat ) as $f ) {
				if ( is_file( $f ) && is_readable( $f ) && filesize( $f ) > 0 && ! preg_match( '/\.(gz|bz2|zip|xz)$/i', $f ) ) {
					$files[ $f ] = $f;
				}
			}
		}
		return array_slice( array_values( $files ), 0, 40 );
	}

	/** Last $bytes of a file as lines (the first, possibly partial, line is dropped). */
	private function read_tail( $file, $bytes ) {
		$fh = @fopen( $file, 'rb' );
		if ( ! $fh ) {
			return array();
		}
		$size = (int) filesize( $file );
		$cut  = false;
		if ( $size > $bytes ) {
			fseek( $fh, -$bytes, SEEK_END );
			$cut = true;
		}
		$data = stream_get_contents( $fh );
		fclose( $fh );
		if ( ! is_string( $data ) ) {
			return array();
		}
		$lines = preg_split( '/\r?\n/', $data );
		if ( $cut ) {
			array_shift( $lines );
		}
		return $lines;
	}

	private function check_logs() {
		$since = (string) P2S_Settings::get( 'since' );
		$files = $this->log_files();
		if ( ! $files ) {
			return $this->res( array( $this->f( 'info', 'logs_none', __( 'No readable server logs found', 'php2shell-guard' ), sprintf( __( 'Many hosts keep logs out of reach of PHP. Add log paths on the Settings tab (one path or glob per line), or ask your host for the access logs from %s onward before they rotate away.', 'php2shell-guard' ), $since ) ) ) );
		}

		$days  = array();
		$urls  = array();
		$crash = array();
		$nacc  = 0;
		$nerr  = 0;
		foreach ( $files as $f ) {
			$lines = $this->read_tail( $f, 8 * 1024 * 1024 );
			$first = null;
			foreach ( $lines as $l ) {
				if ( '' !== trim( $l ) ) {
					$first = $l;
					break;
				}
			}
			if ( null !== $first && self::parse_access_line( $first ) ) {
				$nacc++;
				foreach ( $lines as $l ) {
					$p = self::parse_access_line( $l );
					if ( ! $p ) {
						continue;
					}
					if ( ! isset( $days[ $p['day'] ] ) ) {
						$days[ $p['day'] ] = array( 0, 0 );
					}
					$days[ $p['day'] ][0]++;
					if ( $p['status'] >= 500 ) {
						$days[ $p['day'] ][1]++;
						if ( $p['day'] >= $since ) {
							$urls[ $p['path'] ] = isset( $urls[ $p['path'] ] ) ? $urls[ $p['path'] ] + 1 : 1;
						}
					}
				}
			} else {
				$nerr++;
				foreach ( $lines as $l ) {
					if ( preg_match( self::CRASH_RE, $l ) ) {
						$crash[] = basename( $f ) . ': ' . substr( trim( $l ), 0, 300 );
					}
				}
			}
			unset( $lines );
		}

		$out = array();
		if ( $nacc ) {
			ksort( $days );
			$base = array();
			$win  = array();
			foreach ( $days as $d => $v ) {
				if ( $d < $since ) {
					$base[ $d ] = $v;
				} else {
					$win[ $d ] = $v;
				}
			}
			$base      = array_slice( $base, -7, null, true );
			$win_req   = array_sum( array_column( $win, 0 ) );
			$win_5xx   = array_sum( array_column( $win, 1 ) );
			$win_max   = $win ? max( array_column( $win, 1 ) ) : 0;
			$base_max  = $base ? max( array_column( $base, 1 ) ) : 0;
			$table     = array( 'day         requests    5xx' );
			foreach ( $base as $d => $v ) {
				$table[] = sprintf( '%s  %8d  %5d', $d, $v[0], $v[1] );
			}
			foreach ( $win as $d => $v ) {
				$table[] = sprintf( '%s  %8d  %5d  <- window', $d, $v[0], $v[1] );
			}
			arsort( $urls );
			$top = array();
			foreach ( array_slice( $urls, 0, 10, true ) as $u => $n ) {
				$top[] = $n . '  ' . $u;
			}
			$note = sprintf( __( 'Read the last 8 MB of %d access log(s). If your host writes one log per layer (nginx in front of Apache), requests may be counted twice; the ratios still hold.', 'php2shell-guard' ), $nacc );

			if ( ! $win ) {
				$out[] = $this->f( 'info', 'logs_rotated', __( 'The access logs do not reach the window', 'php2shell-guard' ), sprintf( __( 'No requests on or after %s. The window has probably rotated away; ask the host for archived logs.', 'php2shell-guard' ), $since ) );
			} elseif ( 0 === $win_5xx ) {
				$out[] = $this->f( 'ok', 'logs_5xx_ok', __( 'No 5xx responses in the window', 'php2shell-guard' ), sprintf( __( '%1$d requests since %2$s. Failed memory-corruption attempts usually crash the PHP worker and show up as 500/502 bursts, so a flat zero is a strong reassuring signal. ', 'php2shell-guard' ), $win_req, $since ) . $note, $table );
			} elseif ( ! $base || $win_max > $base_max * 2 ) {
				$out[] = $this->f( 'review', 'logs_5xx_high', __( '5xx responses above the pre-window baseline', 'php2shell-guard' ), sprintf( __( '%1$d 5xx since %2$s (worst day %3$d vs %4$d before). Bursts of 500/502 on random URLs are what failed exploitation attempts look like; a steady trickle on one URL is usually a broken plugin. ', 'php2shell-guard' ), $win_5xx, $since, $win_max, $base_max ) . $note, array_merge( $table, array( '', __( 'Top URLs returning 5xx in the window (count, path):', 'php2shell-guard' ) ), $top ) );
			} else {
				$out[] = $this->f( 'info', 'logs_5xx_normal', __( '5xx responses in line with the baseline', 'php2shell-guard' ), sprintf( __( '%1$d 5xx since %2$s (worst day %3$d vs %4$d before). ', 'php2shell-guard' ), $win_5xx, $since, $win_max, $base_max ) . $note, array_merge( $table, array( '', __( 'Top URLs returning 5xx in the window (count, path):', 'php2shell-guard' ) ), $top ) );
			}
		}
		if ( $nerr ) {
			if ( $crash ) {
				$out[] = $this->f( 'review', 'logs_crash', __( 'PHP worker crashes in the error logs', 'php2shell-guard' ), sprintf( __( '%d crash line(s) (segfault or bus error). A crash is what a failed PHP2Shell attempt leaves behind, but buggy extensions crash too; compare the dates with the window.', 'php2shell-guard' ), count( $crash ) ), array_slice( $crash, -30 ) );
			} else {
				$out[] = $this->f( 'ok', 'logs_crash_ok', __( 'No PHP worker crashes in the error logs', 'php2shell-guard' ), sprintf( __( '%d error log file(s) read.', 'php2shell-guard' ), $nerr ) );
			}
		}
		if ( ! $out ) {
			$out[] = $this->f( 'info', 'logs_empty', __( 'Logs were readable but contained nothing to evaluate', 'php2shell-guard' ) );
		}
		return $this->res( $out );
	}
}
