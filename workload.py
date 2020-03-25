import time
import psutil
import json
import os

if __name__ == '__main__':
    cpu_utl = []
    mem_utl = []
    print('start: ')
    try:
        while True:
            cpu = psutil.cpu_percent(None)
            mem = psutil.virtual_memory()
            print(cpu)
            print(mem.percent)
            cpu_utl.append(cpu)
            mem_utl.append(mem.percent)
            time.sleep(1)
    except KeyboardInterrupt:
        print('End.')

    path = './record'
    if not os.path.exists(path):
        os.makedirs(path)

    filelist = os.listdir(path)

    dic = {'cpu':cpu_utl, 'mem':mem_utl}
    jstr = json.dumps(dic)
    with open(path + '/data_' + str(len(filelist))+ '.json', 'w') as f:
        f.write(jstr)

    print('Finish.')
