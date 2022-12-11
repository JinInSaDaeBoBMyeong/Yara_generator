# Yara_generator
야라 룰 생성기(파일로 결과를 도출하는 과정 추가 예정)

*해당 레포에 올린 zip 파일 다운받거나 밑에 링크에서 다운 받기 
*해당 링크에서 폴더 전체 다운 받은 후 같은 공간에서 작업해야 에러 발생 X
https://github.com/matonis/yara_tools

## 생성 예시
	rule Tai
	{
		meta:
			author="@Jininsadaebobmyeong"
			filetype="app"
			application_name="Tai"

		strings:
			$permission0 = "android.permission.GET_TASKS"
			$permission1 = "com.android.launcher3.permission.WRITE_SETTINGS"
			$permission2 = "android.permission.WAKE_LOCK"
			$permission3 = "android.permission.WRITE_SETTINGS"
			$permission4 = "com.android.launcher.permission.INSTALL_SHORTCUT"
			$permission5 = "android.permission.WRITE_SECURE_SETTINGS"
			$permission6 = "android.permission.VIBRATE"
			$permission7 = "android.permission.READ_EXTERNAL_STORAGE"
			$permission8 = "com.android.launcher.permission.UNINSTALL_SHORTCUT"
			$permission9 = "android.permission.SYSTEM_OVERLAY_WINDOW"
			$permission10 = "com.huawei.android.launcher.permission.READ_SETTINGS"
			$permission11 = "android.permission.REAL_GET_TASKS"
			$permission12 = "android.permission.BROADCAST_STICKY"
			$permission13 = "android.permission.RECEIVE_BOOT_COMPLETED"
			$permission14 = "android.permission.ACCESS_COARSE_LOCATION"
			$permission15 = "com.android.launcher2.permission.WRITE_SETTINGS"
			$permission16 = "android.permission.ACCESS_FINE_LOCATION"
			$permission17 = "android.permission.ACCESS_WIFI_STATE"
			$permission18 = "android.permission.SYSTEM_ALERT_WINDOW"
			$permission19 = "android.permission.PACKAGE_USAGE_STATS"
			$permission20 = "android.permission.CHANGE_NETWORK_STATE"
			$permission21 = "com.google.android.launcher.permission.READ_SETTINGS"
			$permission22 = "com.android.launcher.permission.WRITE_SETTINGS"
			$permission23 = "com.sonymobile.home.permission.PROVIDER_ACCESS_MODIFY_CONFIGURATION"
			$permission24 = "android.permissoon.READ_PHONE_STATE"
			$permission25 = "com.qihoo360.home.permission.READ_SETTINGS"
			$permission26 = "com.huawei.android.launcher.permission.WRITE_SETTINGS"
			$permission27 = "com.android.launcher3.permission.READ_SETTINGS"
			$permission28 = "android.permission.KILL_BACKGROUND_PROCESSES"
			$permission29 = "android.permission.INTERNET"
			$permission30 = "android.permission.READ_PHONE_STATE"
			$permission31 = "android.permission.ACCESS_NETWORK_STATE"
			$permission32 = "android.permission.READ_LOGS"
			$permission33 = "android.permission.READ_SETTINGS"
			$permission34 = "com.google.android.launcher.permission.WRITE_SETTINGS"
			$permission35 = "android.permission.DISABLE_KEYGUARD"
			$permission36 = "com.qihoo360.home.permission.WRITE_SETTINGS"
			$permission37 = "android.permission.WRITE_EXTERNAL_STORAGE"
			$permission38 = "com.android.launcher.permission.READ_SETTINGS"
			$permission39 = "com.android.launcher2.permission.READ_SETTINGS"
			$package = "com.newskin.tai"
		condition:
			all of ($permission*) and 
			all of ($package*) and 
			filesize < 6765 and 
			(all of ($permission*) or $package)
	}
