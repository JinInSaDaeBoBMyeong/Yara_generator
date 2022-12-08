# Yara_generator
야라 룰 생성기(파일로 결과를 도출하는 과정 추가 예정)

*해당 링크에서 폴더 전체 다운 받은 후 같은 공간에서 작업해야 에러 발생 X
https://github.com/matonis/yara_tools

## 생성 예시
{
        import "androguard"

        rule 123456789
        {
                meta:
                        author="@Jininsadaebobmyeong"
                        application name="앱 이름"


                condition:
                        filesize < 100000 and
                        androguard.permission("android.permission.GET_INTENT_SENDER_INTENT") and
                        androguard.permission("android.permission.PACKAGE_USAGE_STATS") and
                        androguard.permission("android.permission.WRITE_MEDIA_STORAGE") and
                        androguard.permission("android.permission.REQUEST_INSTALL_PACKAGES") and
                        androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE") and
                        androguard.permission("android.permission.INTERACT_ACROSS_USERS_FULL") and
                        androguard.permission("android.permission.CAPTURE_SECURE_VIDEO_OUTPUT") and
                        androguard.permission("android.permission.SET_PROCESS_LIMIT") and
                        androguard.permission("android.permission.CAPTURE_VIDEO_OUTPUT") and
                        androguard.permission("android.permission.ACCESS_BACKGROUND_LOCATION") and
                        androguard.permission("android.permission.RECORD_VIDEO") and
                        androguard.permission("android.permission.READ_CALL_LOG") and
                        androguard.permission("android.permission.CAPTURE_AUDIO_HOTWORD") and
                        androguard.permission("android.permission.READ_EXTERNAL_STORAGE") and
                        androguard.package_name("com1") and
                        androguard.package_name("com2") and
                        androguard.app_name("앱 이름")
}
