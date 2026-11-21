<?php
/**
 * Plugin Name: WP Two-Factor Email
 * Plugin URI: https://github.com/Azanumer/wp-two-factor-email
 * Description: Email one-time-code two-factor authentication for wp-login.php. After a correct password, a 6-digit code is emailed to the user and must be entered to sign in. No app, no TOTP — just email.
 * Version: 1.0.0
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Author: Azan Umer
 * Author URI: https://azanumer.cv
 * License: MIT
 * Text Domain: wp-two-factor-email
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'W2FE_VERSION', '1.0.0' );

function w2fe_get_settings() {
	$defaults = array(
		'code_length'   => 6,
		'code_expiry'   => 10, // minutes
		'max_attempts'  => 5,
		'force_admins'  => true,
		'enabled_roles' => array( 'administrator', 'editor' ),
	);
	$saved = get_option( 'w2fe_settings', array() );
	return wp_parse_args( is_array( $saved ) ? $saved : array(), $defaults );
}

/**
 * Does this user need a code? Admins can be forced; other roles opt in
 * from their profile (when their role is in the enabled list).
 */
function w2fe_user_requires_2fa( $user ) {
	if ( ! $user instanceof WP_User ) {
		return false;
	}
	$settings = w2fe_get_settings();
	if ( $settings['force_admins'] && in_array( 'administrator', (array) $user->roles, true ) ) {
		return true;
	}
	if ( '1' === get_user_meta( $user->ID, 'w2fe_enabled', true ) ) {
		return true;
	}
	return false;
}

/**
 * Generate a code, store only its hash, and email the plain code.
 * Returns true when the email was accepted for delivery.
 */
function w2fe_issue_code( $user ) {
	$settings = w2fe_get_settings();
	$length   = max( 4, min( 8, (int) $settings['code_length'] ) );
	$min      = (int) pow( 10, $length - 1 );
	$max      = (int) pow( 10, $length ) - 1;
	$code     = (string) wp_rand( $min, $max );

	update_user_meta( $user->ID, 'w2fe_code_hash', wp_hash_password( $code ) );
	update_user_meta( $user->ID, 'w2fe_code_expires', time() + ( (int) $settings['code_expiry'] * MINUTE_IN_SECONDS ) );
	update_user_meta( $user->ID, 'w2fe_code_attempts', 0 );

	/* translators: %1$s: site name, %2$d: minutes the code stays valid. */
	$subject = sprintf( __( '[%1$s] Your sign-in code', 'wp-two-factor-email' ), get_bloginfo( 'name' ) );
	$message = sprintf(
		/* translators: 1: user display name, 2: code, 3: minutes, 4: site name. */
		__( "Hi %1\$s,\n\nYour sign-in code for %4\$s is:\n\n%2\$s\n\nIt expires in %3\$d minutes and can be used once. If you didn't try to sign in, ignore this email — your password alone can't complete a sign-in while two-factor authentication is on.\n", 'wp-two-factor-email' ),
		$user->display_name,
		$code,
		(int) $settings['code_expiry'],
		get_bloginfo( 'name' )
	);
	return wp_mail( $user->user_email, $subject, $message );
}

/**
 * Main gate: runs after WordPress has verified the password.
 * - No code submitted yet: issue one and stop the login with an error
 *   that tells the user to re-submit with the code.
 * - Code submitted: verify it (hashed, expiry, attempt cap) and either
 *   let the login through or stop it with an error.
 */
function w2fe_authenticate( $user, $username, $password ) {
	if ( ! $user instanceof WP_User ) {
		return $user; // WP_Error or null — let core handle it.
	}
	if ( ! w2fe_user_requires_2fa( $user ) ) {
		return $user;
	}

	$settings = w2fe_get_settings();
	$code     = isset( $_POST['w2fe_code'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['w2fe_code'] ) ) ) : '';

	if ( '' === $code ) {
		w2fe_issue_code( $user );
		return new WP_Error(
			'w2fe_required',
			sprintf(
				/* translators: %s: user email address. */
				__( 'A 6-digit security code was sent to %s. Enter your username, password and the code below to sign in.', 'wp-two-factor-email' ),
				$user->user_email
			)
		);
	}

	$hash    = get_user_meta( $user->ID, 'w2fe_code_hash', true );
	$expires = (int) get_user_meta( $user->ID, 'w2fe_code_expires', true );

	if ( '' === $hash || time() > $expires ) {
		w2fe_clear_code( $user->ID );
		w2fe_issue_code( $user );
		return new WP_Error(
			'w2fe_code_expired',
			__( 'That code has expired. A fresh code was sent to your email — please sign in again with it.', 'wp-two-factor-email' )
		);
	}

	$attempts = (int) get_user_meta( $user->ID, 'w2fe_code_attempts', true );
	if ( $attempts >= (int) $settings['max_attempts'] ) {
		w2fe_clear_code( $user->ID );
		w2fe_issue_code( $user );
		return new WP_Error(
			'w2fe_too_many_attempts',
			__( 'Too many wrong codes. A fresh code was sent to your email — please sign in again with it.', 'wp-two-factor-email' )
		);
	}

	if ( wp_check_password( $code, $hash ) ) {
		w2fe_clear_code( $user->ID );
		return $user; // Code correct — login proceeds.
	}

	update_user_meta( $user->ID, 'w2fe_code_attempts', $attempts + 1 );
	return new WP_Error(
		'w2fe_code_invalid',
		sprintf(
			/* translators: %d: remaining attempts. */
			__( 'That code is incorrect. %d attempt(s) left before a new code is issued.', 'wp-two-factor-email' ),
			max( 0, (int) $settings['max_attempts'] - $attempts - 1 )
		)
	);
}
add_filter( 'authenticate', 'w2fe_authenticate', 40, 3 );

function w2fe_clear_code( $user_id ) {
	delete_user_meta( $user_id, 'w2fe_code_hash' );
	delete_user_meta( $user_id, 'w2fe_code_expires' );
	delete_user_meta( $user_id, 'w2fe_code_attempts' );
}

/**
 * Code field on the login form (harmless when 2FA doesn't apply).
 */
function w2fe_login_form_field() {
	?>
	<p>
		<label for="w2fe_code"><?php esc_html_e( 'Security code', 'wp-two-factor-email' ); ?> <span class="description">(<?php esc_html_e( 'only if emailed to you', 'wp-two-factor-email' ); ?>)</span><br>
		<input type="text" name="w2fe_code" id="w2fe_code" class="input" inputmode="numeric" autocomplete="one-time-code" size="20"></label>
	</p>
	<?php
}
add_action( 'login_form', 'w2fe_login_form_field' );

/* ------------------------------------------------------------------ */
/* Per-user opt-in (profile)                                           */
/* ------------------------------------------------------------------ */

function w2fe_profile_field( $user ) {
	$settings   = w2fe_get_settings();
	$can_enable = (bool) array_intersect( (array) $user->roles, (array) $settings['enabled_roles'] );
	if ( ! $can_enable ) {
		return;
	}
	$forced = $settings['force_admins'] && in_array( 'administrator', (array) $user->roles, true );
	?>
	<h2><?php esc_html_e( 'Two-Factor Authentication', 'wp-two-factor-email' ); ?></h2>
	<table class="form-table"><tbody>
		<tr>
			<th><label for="w2fe_enabled"><?php esc_html_e( 'Email security code', 'wp-two-factor-email' ); ?></label></th>
			<td>
				<label>
					<input type="checkbox" id="w2fe_enabled" name="w2fe_enabled" value="1" <?php checked( '1', get_user_meta( $user->ID, 'w2fe_enabled', true ) ); ?> <?php disabled( $forced, true ); ?>>
					<?php esc_html_e( 'Require a 6-digit code emailed to me on every sign-in', 'wp-two-factor-email' ); ?>
				</label>
				<?php if ( $forced ) : ?>
					<p class="description"><?php esc_html_e( 'Required for administrators by the site settings.', 'wp-two-factor-email' ); ?></p>
				<?php endif; ?>
			</td>
		</tr>
	</tbody></table>
	<?php
}
add_action( 'show_user_profile', 'w2fe_profile_field' );
add_action( 'edit_user_profile', 'w2fe_profile_field' );

function w2fe_save_profile_field( $user_id ) {
	if ( ! current_user_can( 'edit_user', $user_id ) ) {
		return;
	}
	if ( isset( $_POST['w2fe_enabled'] ) ) {
		update_user_meta( $user_id, 'w2fe_enabled', '1' );
	} else {
		// Only clear it when the field was actually shown.
		$user     = get_userdata( $user_id );
		$settings = w2fe_get_settings();
		if ( $user && array_intersect( (array) $user->roles, (array) $settings['enabled_roles'] ) ) {
			update_user_meta( $user_id, 'w2fe_enabled', '0' );
		}
	}
}
add_action( 'personal_options_update', 'w2fe_save_profile_field' );
add_action( 'edit_user_profile_update', 'w2fe_save_profile_field' );

/* ------------------------------------------------------------------ */
/* Settings page                                                       */
/* ------------------------------------------------------------------ */

function w2fe_register_settings_page() {
	add_options_page(
		__( 'Email 2FA', 'wp-two-factor-email' ),
		__( 'Email 2FA', 'wp-two-factor-email' ),
		'manage_options',
		'wp-two-factor-email',
		'w2fe_render_settings_page'
	);
}
add_action( 'admin_menu', 'w2fe_register_settings_page' );

function w2fe_render_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have permission to access this page.', 'wp-two-factor-email' ) );
	}
	$settings = w2fe_get_settings();
	$message  = '';

	if ( isset( $_POST['w2fe_save'] ) && check_admin_referer( 'w2fe_save_settings' ) ) {
		$roles = isset( $_POST['w2fe_roles'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['w2fe_roles'] ) ) : array();
		$valid = array_keys( wp_roles()->roles );
		$settings = array(
			'code_length'   => max( 4, min( 8, (int) ( $_POST['w2fe_code_length'] ?? 6 ) ) ),
			'code_expiry'   => max( 1, min( 60, (int) ( $_POST['w2fe_code_expiry'] ?? 10 ) ) ),
			'max_attempts'  => max( 1, min( 10, (int) ( $_POST['w2fe_max_attempts'] ?? 5 ) ) ),
			'force_admins'  => ! empty( $_POST['w2fe_force_admins'] ),
			'enabled_roles' => array_values( array_intersect( $roles, $valid ) ),
		);
		update_option( 'w2fe_settings', $settings );
		$message = __( 'Settings saved.', 'wp-two-factor-email' );
	}
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'Email Two-Factor Authentication', 'wp-two-factor-email' ); ?></h1>
		<?php if ( '' !== $message ) : ?>
			<div class="notice notice-success is-dismissible"><p><?php echo esc_html( $message ); ?></p></div>
		<?php endif; ?>
		<p><?php esc_html_e( 'After a correct password, users who have 2FA on receive a one-time code by email and must enter it to sign in. Codes are stored hashed, expire quickly, and are single-use.', 'wp-two-factor-email' ); ?></p>
		<form method="post">
			<?php wp_nonce_field( 'w2fe_save_settings' ); ?>
			<table class="form-table"><tbody>
				<tr>
					<th scope="row"><label for="w2fe_code_length"><?php esc_html_e( 'Code length', 'wp-two-factor-email' ); ?></label></th>
					<td><input type="number" id="w2fe_code_length" name="w2fe_code_length" min="4" max="8" value="<?php echo esc_attr( $settings['code_length'] ); ?>" class="small-text"> <span class="description"><?php esc_html_e( 'Digits, 4–8. Default 6.', 'wp-two-factor-email' ); ?></span></td>
				</tr>
				<tr>
					<th scope="row"><label for="w2fe_code_expiry"><?php esc_html_e( 'Code expiry (minutes)', 'wp-two-factor-email' ); ?></label></th>
					<td><input type="number" id="w2fe_code_expiry" name="w2fe_code_expiry" min="1" max="60" value="<?php echo esc_attr( $settings['code_expiry'] ); ?>" class="small-text"></td>
				</tr>
				<tr>
					<th scope="row"><label for="w2fe_max_attempts"><?php esc_html_e( 'Wrong-code attempts', 'wp-two-factor-email' ); ?></label></th>
					<td><input type="number" id="w2fe_max_attempts" name="w2fe_max_attempts" min="1" max="10" value="<?php echo esc_attr( $settings['max_attempts'] ); ?>" class="small-text"> <span class="description"><?php esc_html_e( 'After this many wrong codes a fresh code is issued.', 'wp-two-factor-email' ); ?></span></td>
				</tr>
				<tr>
					<th scope="row"><label for="w2fe_force_admins"><?php esc_html_e( 'Force for administrators', 'wp-two-factor-email' ); ?></label></th>
					<td><input type="checkbox" id="w2fe_force_admins" name="w2fe_force_admins" value="1" <?php checked( $settings['force_admins'] ); ?>></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Roles that may opt in', 'wp-two-factor-email' ); ?></th>
					<td>
						<?php foreach ( wp_roles()->roles as $slug => $role ) : ?>
							<label style="display:block;"><input type="checkbox" name="w2fe_roles[]" value="<?php echo esc_attr( $slug ); ?>" <?php checked( in_array( $slug, (array) $settings['enabled_roles'], true ) ); ?>> <?php echo esc_html( translate_user_role( $role['name'] ) ); ?></label>
						<?php endforeach; ?>
						<p class="description"><?php esc_html_e( 'Users in these roles see the opt-in checkbox on their profile page.', 'wp-two-factor-email' ); ?></p>
					</td>
				</tr>
			</tbody></table>
			<p><input type="submit" name="w2fe_save" class="button button-primary" value="<?php esc_attr_e( 'Save Settings', 'wp-two-factor-email' ); ?>"></p>
		</form>
	</div>
	<?php
}
