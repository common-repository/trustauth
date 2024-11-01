=== Plugin Name ===
Contributors: romaimperator
Donate link: http://trustauth.com/
Tags: admin, plugin, security, administration, login, authentication, trustauth, TrustAuth
Requires at least: 3.3
Tested up to: 3.4
Stable tag: 1.2.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

This plugin adds support for logging into WordPress using TrustAuth.

== Description ==

TrustAuth is an excellent way to keep your blog secure. TrustAuth uses the same technology as SSL to authenticate users to a
website instead of using passwords. This plugin allows you to use TrustAuth to login to your blog.

Note: The TrustAuth browser plugin is required to use TrustAuth. You can find a link to that here on [the project homepage](http://trustauth.com).
Your browser may not be supported yet.

== Installation ==

This section describes how to install the plugin and get it working.

e.g.

1. Upload the folder `trustauth` to the `/wp-content/plugins/` directory
1. Activate the plugin through the 'Plugins' menu in WordPress

== Frequently Asked Questions ==

= Is there a TrustAuth plugin for &lt;insert browser&gt;? =

Currently the only browser that is support is Firefox but soon there will be plugins for Chrome and other browsers.

= I'm having trouble with the WordPress plugin. Where can I go for support? =

You can view the support page for the TrustAuth plugin on wordpress.org or view the issues page on [github](https://github.com/romaimperator/trustauth-wordpress/issues).

= I'm having trouble with the browser plugin. Where can I go for support? =

You can view the support page for the TrustAuth Firefox plugin on [github](https://github.com/romaimperator/trustauth-firefox/issues).

== Screenshots ==

There are no screenshots.

== Changelog ==

= 1.2.0 =
* Fixed problem where a user could reset their password but still not be
  able to login if they didn't have their TrustAuth key and had disabled
  password logins. Now when you reset your password, password logins are
  automatically re-enabled.
* Administrators can now modify other users' TrustAuth settings. They
  can do everything except assign new keys.
* Users can now remove their TrustAuth key.

= 1.1.0 =
* Added deletion of assigned TrustAuth keys when deleting a user
  account.
* Added option to disable password logins.

= 1.0.4 =
* Updated libtrustauth.php to support two other methods for generating
  random numbers. The plugin should now supports versions of PHP older
  than 5.3.0 that do not have openssl_random_pseudo_bytes().

= 1.0.3 =
* Ok final bug fix. libtrustauth.php still had the old SITE_DOMAIN
  constant.

= 1.0.2 =
* Fixed new bug with the domain name. Now parses from the option 'home'.

= 1.0.1 =
* Fixed bug with the domain name and updated libtrustauth.php. Now
  parses the domain name from WP_HOME.

= 1.0.0 =
* Initial version of the plugin.

== Upgrade Notice ==

= 1.2.0 =
* Fixed problem where a user could be locked out of their account
  if she had disabled password logins and could not login with
  TrustAuth even after resetting her password. Now password logins are
  automatically re-enabled after the new password is set.
* See changelog for new features.

= 1.1.0 =
* Adds option to disable password login for your account. Also adds
  deletion of the assigned TrustAuth keys when a user account is
  deleted.

= 1.0.4 =
* If you are using a version of PHP that does not have
  openssl_random_pseudo_bytes() (i.e. versions older than 5.3.0) this
  should allow you to use the plugin. If you are running PHP > 5.3.0
  this update is not urgent.

= 1.0.3 =
* Fixing the bug the last version did not fix.

= 1.0.2 =
* The last version didn't actually fix the problem but instead
  introduced a new problem. This is the fix.

= 1.0.1 =
* Authenication won't work if you are using a virtual server to host
  your blog. libtrustauth uses $_SERVER['SERVER_NAME'] to get the domain
  which on a virtual host returns the virtual host name which could be
  something like "localhost" if you are proxying your traffic like I am
  on the TrustAuth blog. The main site is actually a separate nginx site
  from the blog despite being trustauth.com/blog.
