<?php
/*
Plugin Name: TrustAuth
Plugin URI: http://trustauth.com
Description: This plugin adds TrustAuth authentication to a WordPress blog.
Version: 1.2.0
Author: Dan Fox
Author URI: http://romaimperator.com
License: GPL2
*/
/*  Copyright 2012  Dan Fox  (email : romaimperator@gmail.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

global $wpdb;
define("TRUSTAUTH_TABLE_NAME", $wpdb->prefix . "trustauth");
define("TRUSTAUTH_COOKIE_NAME", "trustauth-wordpress");
define("TRUSTAUTH_COOKIE_EXPIRATION", 30);
define("TRUSTAUTH_SALT_OPTION_NAME", "trustauth_salt");
define("TRUSTAUTH_DB_VERSION_OPTION_NAME", "trustauth_db_version");
define("TRUSTAUTH_NO_PASSWORD_NAME", "trustauth_no_password");

set_include_path(get_include_path() . PATH_SEPARATOR . ABSPATH . 'wp-content/plugins/trustauth/');
require_once 'libtrustauth.php';
restore_include_path();

/**
 * Inserts the public key for the given user id if the user doesn't have one yet, or updates
 * it to the given public key if the user already has one.
 *
 * @param {int} user_id the id of the user this key belongs to
 * @param {string} public_key the public key to assign this user
 */
function trustauth_insert_or_update_key($user_id, $public_key) {
    if (empty($public_key)) { return; }
    global $wpdb;

    if (trustauth_fetch_public_key($user_id) == null) {
        $wpdb->insert(TRUSTAUTH_TABLE_NAME, array('user_id' => $user_id, 'public_key' => $public_key), array('%s', '%s'));
    } else {
        $wpdb->update(TRUSTAUTH_TABLE_NAME, array('public_key' => $public_key), array('user_id' => $user_id), array('%s'));
    }
}

/**
 * Fetches the public key assigned to the given user id.
 *
 * @param {int} user_id the id of the user to fetch the key for
 * @return {string} the public_key or null if there isn't one for the user
 */
function trustauth_fetch_public_key($user_id) {
    global $wpdb;

    $sql = $wpdb->prepare('SELECT public_key FROM ' . TRUSTAUTH_TABLE_NAME . ' WHERE user_id=%s', $user_id);
    return $wpdb->get_var($sql);
}

/**
 * Deletes the public keys belonging to $user_id.
 *
 * @param {int} $user_id the id of the user to delete keys for
 */
function trustauth_delete_public_key($user_id) {
    global $wpdb;

    $sql = $wpdb->prepare("DELETE FROM " . TRUSTAUTH_TABLE_NAME . " WHERE user_id=%s", $user_id);
    $wpdb->query($sql);
}

/**
 * Adds the TrustAuth fields to the login form.
 */
function trustauth_login() {
    $parsed_url = parse_url(get_option('home'));
    $challenge = TrustAuth::get_challenge($parsed_url['host']);
    setcookie(TRUSTAUTH_COOKIE_NAME, hash('sha256', $challenge . get_option(TRUSTAUTH_SALT_OPTION_NAME)), time() + TRUSTAUTH_COOKIE_EXPIRATION, COOKIEPATH, COOKIE_DOMAIN, false, true);
    echo TrustAuth::authenticate_form(array('challenge' => $challenge));
}

/**
 * Adds the TrustAuth fields to the edit user form.
 */
function trustauth_edit_user($user) {
    include('edit_user_form.php');
}

/**
 * Gets the user meta data or adds the default if it's not been set.
 *
 * @param {int} $user_id the id of the user the meta data belongs to
 * @param {string} $meta_key the name of the meta data key
 * @param {boolean} $single If true return value of meta data field, if false return an array.
 * @param {mixed} $default the default value to use when adding the key
 * @param {boolean} $unique If created should key have only one value? True by default
 * @return {mixed} the value if it was set or $default if it wasn't
 */
function trustauth_get_or_add_user_meta($user_id, $meta_key, $single, $default, $unique = true) {
    $value = get_user_meta($user_id, $meta_key, $single);

    if ( $value == "" ) {
        add_user_meta($user_id, $meta_key, $default, $unique);
        return $default;
    } else {
        return $value;
    }
}

/**
 * Authenticates the user's login info with TrustAuth.
 */
function trustauth_authentication($user, $username, $password) {
    // If an earlier function authenticates a user then skip TrustAuth
    if (is_a($user, 'WP_User')) { return $user; }

    // Get the data for the $username
    if ( !empty($username) ) {
        $userdata = get_user_by('login', $username);

        if ( !$userdata ) {
            return new WP_Error('invalid_username', sprintf(__('<strong>ERROR</strong>: Invalid username. <a href="%s" title="Password Lost and Found">Lost your password</a>?'), wp_lostpassword_url()));
        }
    } else {
        $error = new WP_Error();
        $error->add('empty_username', __('<strong>ERROR</strong>: The username field is empty.'));
        $error->add('empty_password', __('<strong>ERROR</strong>: The password field is empty.'));
        return $error;
    }

    $password_logins_allowed = ! trustauth_get_or_add_user_meta($userdata->ID, TRUSTAUTH_NO_PASSWORD_NAME, true, false);

    // First we check to see if the user is allowing password logins.
    if ( $password_logins_allowed && !empty($password) ) {
        // If the user is allowing password logins and the password field is not empty by-pass TrustAuth and run a normal login
        return wp_authenticate_username_password($user, $username, $password);
    } else {
        $reset_password_html = sprintf(' <a href="%s" title="Password Lost and Found">Lost your password</a>?', wp_lostpassword_url());
        // If either no password logins are allowed or the password field is empty then try TrustAuth
        if ( isset($_POST['ta-response']) && !empty($_POST['ta-response']) && isset($_POST['ta-challenge']) && !empty($_POST['ta-challenge']) && isset($_COOKIE[TRUSTAUTH_COOKIE_NAME]) ) {
            if (hash('sha256', $_POST['ta-challenge'] . get_option(TRUSTAUTH_SALT_OPTION_NAME)) === $_COOKIE[TRUSTAUTH_COOKIE_NAME]) {
                try {
                    if (TrustAuth::verify($_POST['ta-challenge'], $_POST['ta-response'], trustauth_fetch_public_key($userdata->ID))) {
                        $user = new WP_User($userdata->ID);
                    } else {
                        $user = new WP_Error('trustauth_login_error', __('<strong>ERROR</strong>: There was an error verifying the TrustAuth response. Try refreshing the page and logging in again. ' . $reset_password_html));
                    }
                } catch (TAException $e) {
                    $user = new WP_Error('trustauth_exception', __('<strong>ERROR</strong>: ' . $e->get_user_message() . $reset_password_html));
                }
            } else {
                $user = new WP_Error('trustauth_hash_error', __('<strong>ERROR</strong>: Could not validate the TrustAuth challenge. Try refreshing the page and logging in again.' . $reset_password_html));
            }
            return $user;
        } else {
            if ( $password_logins_allowed ) {
                return new WP_Error('trustauth_missing', __('<strong>ERROR</strong>: Both the password and TrustAuth data are missing. Is your TrustAuth add-on locked or did you mean to type a password?' . $reset_password_html));
            } else {
                return new WP_Error('trustauth_missing', __('<strong>ERROR</strong>: Password logins are disabled and the TrustAuth data is missing. Is your TrustAuth add-on locked?' . $reset_password_html));
            }
        }
    }
}

/**
 * Checks for a key to add for the user.
 */
function trustauth_after_login($user_login) {
    $user = get_user_by('login', $user_login);
    $public_key = trustauth_fetch_public_key($user->ID);
    if ( isset($user_login) && isset($_POST['ta-key']) && $public_key == null) {
        trustauth_insert_or_update_key($user->ID, $_POST['ta-key']);
    }
}

/**
 * Updates the public_key for the user when edited.
 */
function trustauth_profile_update($user_id) {
    if ( isset($_POST['ta-key']) ) {
        trustauth_insert_or_update_key($user_id, $_POST['ta-key']);
    }

    if ( isset($_POST['ta-no-password']) ) {
        if (trustauth_fetch_public_key($user_id) != null) {
            update_user_meta($user_id, TRUSTAUTH_NO_PASSWORD_NAME, true);
        } else {
            return new WP_Error('trustauth_no_password_error', __('You must have a TrustAuth key assigned before password login can be disabled.'));
        }
    } else {
        update_user_meta($user_id, TRUSTAUTH_NO_PASSWORD_NAME, false);
    }

    if ( isset($_POST['ta-remove-key']) ) {
        if ( trustauth_fetch_public_key($user_id) != null ) {
            update_user_meta($user_id, TRUSTAUTH_NO_PASSWORD_NAME, false);
            trustauth_delete_public_key($user_id);
        }
    }
}

/**
 * Creates the tables needed for TrustAuth.
 */
function trustauth_create_tables() {
    $sql = "CREATE TABLE " . TRUSTAUTH_TABLE_NAME . " (
      user_id bigint(20) unsigned NOT NULL,
      public_key text NOT NULL,
      PRIMARY KEY  (user_id)
    );";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
    update_option(TRUSTAUTH_DB_VERSION_OPTION_NAME, '1.0.0');
}

/**
 * Deletes the tables needed for TrustAuth.
 */
function trustauth_delete_tables() {
    global $wpdb;

    $sql = "DROP TABLE IF EXISTS " . TRUSTAUTH_TABLE_NAME . ";";
    $wpdb->query($sql);
    delete_option(TRUSTAUTH_DB_VERSION_OPTION_NAME);
}

/**
 * Activates the TrustAuth plugin.
 */
function trustauth_activation() {
    update_option(TRUSTAUTH_SALT_OPTION_NAME, TrustAuth::get_random_value());
    trustauth_create_tables();
}

/**
 * Deactivates the TrustAuth plugin.
 */
function trustauth_deactivation() {
    delete_option(TRUSTAUTH_SALT_OPTION_NAME);
}

/**
 * Uninstalls the TrustAuth plugin.
 */
function trustauth_uninstall() {
    delete_option(TRUSTAUTH_SALT_OPTION_NAME);
    trustauth_delete_tables();
}

/**
 * Removes any TrustAuth keys for the deleted user.
 *
 * @param {int} $user_id the id of the user being deleted
 */
function trustauth_delete_user($user_id) {
    trustauth_delete_public_key($user_id);
}

/**
 * Re-enables password logins when the user resets her password.
 *
 * @param {WP_User} $user the user who reset his password
 * @param {string} $new_pass the plaintext of the new password
 */
function trustauth_password_reset($user, $new_pass) {
    update_user_meta($user->ID, TRUSTAUTH_NO_PASSWORD_NAME, false);
}

// Register all of the hooks
add_action('login_form','trustauth_login');
add_action('show_user_profile', 'trustauth_edit_user');
add_action('edit_user_profile', 'trustauth_edit_user');
add_action('profile_update', 'trustauth_profile_update');
add_action('authenticate','trustauth_authentication', 20, 3);
remove_filter('authenticate', 'wp_authenticate_username_password', 20, 3);

add_action('wp_login', 'trustauth_after_login');
add_action('delete_user', 'trustauth_delete_user');
add_action('password_reset', 'trustauth_password_reset', 10, 2);

register_activation_hook('trustauth/trustauth.php', 'trustauth_activation');
register_deactivation_hook('trustauth/trustauth.php', 'trustauth_deactivation');
register_uninstall_hook('trustauth/trustauth.php', 'trustauth_uninstall');
?>
