from androguard.core.bytecodes.apk import APK
import json
import os
import hashlib
import yara_generator

sample_path = r'sample'
json_path = r'json'
fileEx = r'.apk'
apk_path = []

def file_size(apk_file):
    i = os.path.getsize(apk_file)
    filesize = int(round(i/1024,2))
    return filesize
#file hash(json 제목 MD5로 하기 위해)
def file_hash(apk_file):
    f = open(apk_file, 'r')
    data = f.read()
    hash = hashlib.md5(data).hexdigest()
    return hash

def file_load():
    if not os.path.isdir(sample_path):
        os.mkdir(sample_path)
    elif not os.path.isdir(json_path):
        os.mkdir(json_path)
    else:
        try:
            apk_list = [file for file in os.listdir(sample_path) if file.endswith(fileEx)]
            #file path 
            return apk_list

        except Exception as e:
            print("[+] File Load Fail : {}".format(e))
#APK Analyze           
def apk_analyze(apk_list):
    for al in range(len(apk_list)):
        #file path
        apk_path.append(sample_path + str('/') + apk_list[al])
        #file_hash
        # file_hash(apk_path[al])

        a = APK(apk_path[al])
        print("[+] 파일 분석 완료")
        json_yara_make(a, apk_list[al])
        print("[+]" + apk_list[al] + "파일 json 변환 완료 ")
#Json make
def json_yara_make(apk_file, apk_list):
    apk_size= file_size(sample_path + str("/") +apk_list)
    # Yara 룰 제작
    yara_generator.start(apk_file, apk_size, apk_list[:-4])
    d = {}
    d["app_name"] = apk_file.get_app_name()
    d["package_name"] = apk_file.get_package()
    d['permissions'] = apk_file.get_permissions()
    d['activities'] = apk_file.get_activities()
    d['receivers'] = apk_file.get_receivers()
    d['providers'] = apk_file.get_providers()
    d['main_activity'] = apk_file.get_main_activity()
    d['services'] = apk_file.get_services()
    d['max_sdk_version'] = apk_file.get_max_sdk_version()
    d['min_sdk_version'] = apk_file.get_min_sdk_version()
    d['version_code'] = apk_file.get_androidversion_code()
    d['libraries'] = [x for x in apk_file.get_libraries()]
    d['target_sdk_version'] = apk_file.get_target_sdk_version()
    d['filesize'] = str(apk_size) + "KB"
    json_name = json_path +str("/") + str(apk_list[:-4]) + str(".json")
    with open(json_name, "w") as json_file:
        json.dump(d, json_file, indent=4, sort_keys=True)

if __name__ == "__main__":
    fl = file_load()
    apk_analyze(fl)
