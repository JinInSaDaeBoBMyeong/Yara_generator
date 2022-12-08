import yara
import yara_tools

#md5 예시 
sample_name = '123456789'
app_name = '앱 이름'
apk_package = ['com1', 'com2']
# Permisison 예시(상위 15개로 넘겨받을 예정)
andro_permission = ['android.permission.GET_INTENT_SENDER_INTENT', 'android.permission.PACKAGE_USAGE_STATS', 'android.permission.WRITE_MEDIA_STORAGE',
                     'android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.WRITE_EXTERNAL_STORAGE', 'android.permission.INTERACT_ACROSS_USERS_FULL',
                     'android.permission.CAPTURE_SECURE_VIDEO_OUTPUT', 'android.permission.SET_PROCESS_LIMIT', 'android.permission.CAPTURE_VIDEO_OUTPUT', 'android.permission.ACCESS_BACKGROUND_LOCATION',
                     'android.permission.RECORD_VIDEO', 'android.permission.READ_CALL_LOG', 'android.permission.CAPTURE_AUDIO_HOTWORD', 'android.permission.READ_EXTERNAL_STORAGE']

#import 할 모듈
rule= yara_tools.create_rule(name=sample_name)
rule.add_import(name='androguard')
rule.set_default_boolean(value='and')

#룰의 메타 정보
rule.add_meta(key='author', value='@Jininsadaebobmyeong')
rule.add_meta(key = 'application name', value=app_name)

rule.add_condition(condition="filesize < 100000")

#Permission Rule
for i in range(len(andro_permission)):
    permission_rule = 'androguard.permission("{}")'.format(andro_permission[i])
    rule.add_condition(condition = permission_rule)
#package
for ap in range(len(apk_package)):
    apk_package_rule = 'androguard.package_name("{}")'.format(apk_package[ap])
    rule.add_condition(condition=apk_package_rule)
#app name
app_name_rule = 'androguard.app_name("{}")'.format(app_name)
rule.add_condition(condition=app_name_rule)

generated_rule = rule.build_rule()

try:
# compiled_rule = yara.compile(source=generated_rule)
    print(generated_rule)
    print("[+] SUCCESS: IT WORKED!")
except Exception as e:
    print("[+] Failed :", e)


