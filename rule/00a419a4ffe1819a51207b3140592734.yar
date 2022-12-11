
rule SkyHero
{
	meta:
		author="@Jininsadaebobmyeong"
		filetype="app"
		application_name="SkyHero"

	strings:
		$permission0 = "android.permission.GET_TASKS"
		$permission1 = "android.permission.WAKE_LOCK"
		$permission2 = "com.android.launcher.permission.INSTALL_SHORTCUT"
		$permission3 = "org.adw.launcher.permission.READ_SETTINGS"
		$permission4 = "android.permission.VIBRATE"
		$permission5 = "com.android.launcher.permission.UNINSTALL_SHORTCUT"
		$permission6 = "com.android.browser.permission.WRITE_HISTORY_BOOKMARKS"
		$permission7 = "android.permission.GET_ACCOUNTS"
		$permission8 = "android.permission.INSTALL_PACKAGES"
		$permission9 = "android.permission.SET_WALLPAPER"
		$permission10 = "android.permission.RECEIVE_BOOT_COMPLETED"
		$permission11 = "android.permission.FLASHLIGHT"
		$permission12 = "com.htc.launcher.permission.READ_SETTINGS"
		$permission13 = "android.permission.ACCESS_COARSE_LOCATION"
		$permission14 = "android.permission.ACCESS_FINE_LOCATION"
		$permission15 = "android.permission.ACCESS_WIFI_STATE"
		$permission16 = "com.motorola.dlauncher.permission.INSTALL_SHORTCUT"
		$permission17 = "android.permission.MOUNT_UNMOUNT_FILESYSTEMS"
		$permission18 = "com.motorola.launcher.permission.READ_SETTINGS"
		$permission19 = "com.android.browser.permission.READ_HISTORY_BOOKMARKS"
		$permission20 = "com.lge.launcher.permission.READ_SETTINGS"
		$permission21 = "com.motorola.dlauncher.permission.READ_SETTINGS"
		$permission22 = "android.permission.INTERNET"
		$permission23 = "android.permission.READ_PHONE_STATE"
		$permission24 = "android.permission.ACCESS_NETWORK_STATE"
		$permission25 = "com.lge.launcher.permission.INSTALL_SHORTCUT"
		$permission26 = "com.android.launcher.permission.READ_SETTINGS"
		$permission27 = "android.permission.CALL_PHONE"
		$permission28 = "android.permission.WRITE_EXTERNAL_STORAGE"
		$permission29 = "com.fede.launcher.permission.READ_SETTINGS"
		$permission30 = "com.motorola.launcher.permission.INSTALL_SHORTCUT"
		$package = "com.test.t000004"

	condition:
		all of ($permission*) and 
		all of ($package*) and 
		filesize < 4509 and 
		(all of ($permission*) or $package)

}