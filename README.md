# xibo-cms Missing Authentication for Critical Function (CWE-306)
--

## Overview:

- **Vulnerability Name**: Unauthenticated Administrative Password Reset in /install Routes
- **Target Software**: Xibo CMS (v4.4.4)
- **Severity**: CRITICAL (9.8/10)
- **Vulnerability Type**: Missing Authentication for Critical Function (CWE-306)
- **Status**: Verified via Proof of Concept (PoC)

--

## Vulnerability Description:

The Xibo CMS installer (accessible via /install/) contains a logic flaw that allows any user on the internet to reset the primary administrator's password.

While the installer correctly checks if the system is already installed during the initial steps (Steps 1, 2, and 3), it fails to perform these checks in the later steps. Specifically, Step 5 of the installer processes user-provided credentials and updates the database record for the main administrator (UserID 1) without requiring any session tokens, existing passwords, or verification that the installation is actually in progress.

--

## Technical Analysis:

The Entry Point The installer application is defined in web/install/index.php. It uses the Slim framework to handle routes defined in lib/routes-install.php.

The Vulnerable Route In lib/routes-install.php, the handler for /{step} contains a switch statement. Notice that Step 1-3 have checks for $settingsExists, but Step 5 does not:

1 // File: lib/routes-install.php
2 switch ($step) {
3     case 1:
4     case 2:
5     case 3:
6         if ($settingsExists) { // This check is correct
7             throw new InstallationError(__('The CMS has already been installed.'));
8         }
9         ...
10 case 5:
11 unset($_SESSION['error']);
12 // Create a user account
13 try {
14 // VULNERABILITY: No check for $settingsExists here!
15 $install->step5($request, $response);
16 return $response->withRedirect(...);

The Database Update The step5 method in lib/Helper/Install.php takes input directly from the request and executes a raw SQL UPDATE on the database. It specifically targets UserID 1, which is the default ID for the Super Administrator:

1 // File: lib/Helper/Install.php
2 public function step5(Request $request, Response $response) : Response {
3     $sanitizedParams = $this->getSanitizer($request->getParams());
4     $username = $sanitizedParams->getString('admin_username');
5     $password = $sanitizedParams->getString('admin_password');
6
7     // ... validation checks for empty strings ...
8
9     $dbh = $store->getConnection();
10 // VULNERABILITY: Directly updates UserID 1
11 $sth = $dbh->prepare('UPDATE user SET UserName = :username, UserPassword = :password WHERE UserID = 1
LIMIT 1');
12 $sth->execute(array(
13 'username' => $username,
14 'password' => md5($password) // Note: Uses MD5 which is also an older security practice
15 ));
16 }

--

## Impact:

An unauthenticated attacker can gain Full Administrative Control over the Xibo CMS.

  - **System Takeover**: The attacker can change the admin username and password.
  - **RCE on Players**: Once logged in, an attacker can use the "Shell Command" module to execute arbitrary code on all connected digital signage displays (Players).
  - **Data Breach**: All media, datasets, and user information can be stolen.
  - **Persistence**: The attacker can create new admin accounts to maintain access even if the primary password is recovered.

--

## Remediation Recommendation:

The developers should implement a Global Guard at the beginning of the installer route handler.

**Proposed Fix**:

In lib/routes-install.php, add a check at the top of the route closure:

$app->map(['GET', 'POST'],'/{step}', function(Request $request, Response $response, $step = 1) use ($app) {
// ...
$settingsExists = file_exists(PROJECT_ROOT . '/web/settings.php');

// NEW SECURITY CHECK:
if ($settingsExists && $step != 7) {
throw new InstallationError("Access Denied: CMS is already installed.");
}
// ...

Additionally, the installer should use a more secure hashing algorithm (like Bcrypt) instead of MD5 for the initial password setup.

--

## Researcher Information:

**Name**: soulless
**Date**: June 17, 2026
**Verification**: Confirmed on local Docker laboratory environment.
