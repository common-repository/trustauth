<?php
  require_once 'libtrustauth.php';

if ( isset($user) ) {
  $no_password = trustauth_get_or_add_user_meta($user->ID, TRUSTAUTH_NO_PASSWORD_NAME, true, false);
  $has_trustauth_key = trustauth_fetch_public_key($user->ID) !== null;
  $current_user = wp_get_current_user();

  echo '
<h3>TrustAuth</h3>
<table class="form-table">';

// if the user has a key
if ($has_trustauth_key) :
// Show the password disable / enable checkbox
   echo '
<tr>
  <th><label for="ta-no-password">Password Logins</label></th>
  <td>
  <p>
    <label for="ta-no-password">
    <input name="ta-no-password" type="checkbox" value="false" ', ($no_password) ? 'checked="true"' : '', '/>
      ',__('Disable password logins for this account. This requires that a TrustAuth key has been assigned to this account.', 'trustauth'),'
    </label>
  </p>
  </td>
</tr>';

// Show the remove key checkbox
  echo '
<tr>
  <th><label for="ta-remove-key">Remove TrustAuth Key</label></th>
  <td>
  <p>
    <label for="ta-remove-key">
    <input name="ta-remove-key" type="checkbox" value="true"/>
      ',__('Remove the TrustAuth key from this account. <strong>Note:</strong> This automatically re-enables password logins.', 'trustauth'),'
    </label>
  </p>
  </td>
</tr>';
else :

// If the current user is editting their own page also show the add TrustAuth key button.
if ($user->ID === $current_user->ID) :
  echo '
<tr>
  <th></th>
  <td>
    <p style="margin-top:0;">'.__('Adding your TrustAuth key allows you to login to WordPress using TrustAuth.', 'trustauth').'</p>
    <p>',
      TrustAuth::register_form(array('use_html5' => false)),
    '</p>
  </td>
</tr>';
else :
  echo '
<tr>
  <th></th>
  <td>
    <p style="margin-top:0;">'.__('This user does not have a TrustAuth key.', 'trustauth').'</p>
  </td>
</tr>';
endif;

endif;
  echo '
</table>
';

} else {
// If we reach here the $user variable wasn't properly set.
  echo '
<h3>TrustAuth</h3>
<table class="form-table">
<tr>
  <th><label for="ta-error"><strong>ERROR:</strong></label></th>
  <td>
  <p>
    <label for="ta-error">
    <input name="ta-error" type="checkbox" value="true"/>
      ',__('An error occured while trying to create the forms for the TrustAuth plugin.', 'trustauth'),'
    </label>
  </p>
  </td>
</tr>
</table>';
}
?>
