# Description:
# This script loads json log files produced by Suricata IDS and processes these to produce a zipped csv file
# This CSV file covers event of the timerange of the previous 12 full hours
# 4ntiG0nu5


#import modules

import json
import pandas as pd
import numpy as np
import datetime
#rom datetime import timedelta 
#from datetime import datetime
import os 
import copy
import re
import gzip
import shutil
import sys
from zipfile import ZipFile

#define function to grab files
def getfiles(dirpath):
    a = [s for s in os.listdir(dirpath)
         if os.path.isfile(os.path.join(dirpath, s))]
    a.sort(key=lambda s: os.path.getmtime(os.path.join(dirpath, s)))
    return a

#Initialize important variables
b = []
#Get jsons from suricata directory
b = getfiles("/nsm/suricata")
c = []
#Deep copy to process
c = copy.deepcopy(b)

#Load to dataframes
df1 = pd.DataFrame (b,columns=['time'])
df2 = pd.DataFrame (c,columns=['path'])
df3 = pd.concat([df1, df2], axis=1)

#Cleaning dataframe
def clean_text(text):
    text = re.sub(r'eve-', '', text) # Cleaning up 
    text = re.sub(r'.json', '', text)  # Cleaning up 
    return text
df3['time'] = df3['time'].apply(lambda x: clean_text(x))
df3.head()
#
#Convert to datetime
df3['time'] = pd.to_datetime(df3['time'])

#Preparing to filter by time
#This assumes time is set to UTC
end_remove= datetime.datetime.now()
start_remove= datetime.datetime.now() - datetime.timedelta(hours = 14)

#Filter
#Theres a reason 14hrs is selected
#Reduces data we have to process
df4 = df3[(df3['time'] >= start_remove)]
df4 =df4.reset_index(drop=True)

#Cleaning text
def clean_text(text):
    text = re.sub(r'eve-', '/nsm/suricata/eve-', text) # Cleaning up 
    return text
df4['path'] = df4['path'].apply(lambda x: clean_text(x))
df4.head()

d = []
d = df4['path'].tolist()

#Grab alert from the nested json
df5 = pd.concat([pd.read_json(f, lines=True) for f in d], ignore_index = True)
df6 = (df5["alert"].apply(pd.Series))
df5 = df5.assign(signature = df6['signature'])
df5 = df5.assign(signature_id = df6['signature_id'])
df5 = df5.assign(category = df6['category'])

#Convert UTC time to Nairobi time
df5['timestamp'] = pd.to_datetime(df5.timestamp).dt.tz_convert('Africa/Nairobi')
df5['timestamp'] = df5['timestamp'].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S'))
df5['timestamp'] = pd.to_datetime(df5['timestamp'])

#Select columns to be written to csv
cols_to_keep = ['timestamp', 'signature_id', 'signature', 'category', 
                'src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'app_proto']
df5 = df5[cols_to_keep]

#Final filtering by time
#Ensures 12hrs period
end_remove_csv = datetime.datetime.now() + datetime.timedelta(hours = 3)
end_remove_csv= end_remove_csv.replace(microsecond=0, second=0, minute=0)
start_remove_csv = datetime.datetime.now() - datetime.timedelta(hours = 9)
start_remove_csv= start_remove_csv.replace(microsecond=0, second=0, minute=0)


df7 = df5[(df5['timestamp'] >= start_remove_csv)]
df7 =df7.reset_index(drop=True)
df7 = df7[(df7['timestamp'] <= end_remove_csv)]
df7 =df7.reset_index(drop=True)

#Time variables to append to csv report
start_remove_output= str(start_remove_csv)
end_remove_csv_output= str(end_remove_csv)

#Get Cover Page
df_cover = pd.read_csv('/home/antigonus/Work/Dev/pivot_table_so/so_cover_page.csv')

#Pivot Tables
table1 = pd.pivot_table(data=df7,index=['category', 'src_ip', 'dest_ip'],aggfunc={'category':np.count_nonzero})
table2 = pd.pivot_table(data=df7,index=['signature', 'src_ip', 'dest_ip'],aggfunc={'signature':np.count_nonzero})
table3 = pd.pivot_table(data=df7,index=['dest_ip', 'src_ip', 'signature'],aggfunc={'signature':np.count_nonzero})


with pd.ExcelWriter('SOC_suricata_report' + ' ' + start_remove_output +  ' ' + 'to'+ ' ' +  end_remove_csv_output +  '.xlsx', engine='xlsxwriter') as writer:  
    #
    df_cover.to_excel(writer, sheet_name='Cover Page', index=False, header=False)
    workbook = writer.book
    worksheet = writer.sheets['Cover Page']
    worksheet.set_column('A:A', 30)
    worksheet.set_column('B:B', 45)
    worksheet.set_column('C:C', 10)
    #
    df7.to_excel(writer, sheet_name='Detailed Connections', index=False)
    workbook = writer.book
    worksheet = writer.sheets['Detailed Connections']
    worksheet.set_column('A:B', 15)
    worksheet.set_column('C:C', 50)
    worksheet.set_column('D:D', 20)
    worksheet.set_column('E:J', 10)
    #
    table1.to_excel(writer, sheet_name='Analysis by Category')
    workbook = writer.book
    worksheet = writer.sheets['Analysis by Category']
    worksheet.set_column('A:A', 27)
    worksheet.set_column('B:D', 18) 
    #
    table2.to_excel(writer, sheet_name='Analysis by Signature')
    workbook = writer.book
    worksheet = writer.sheets['Analysis by Signature']
    worksheet.set_column('A:A', 60)
    worksheet.set_column('B:D', 18) 
    #
    table3.to_excel(writer, sheet_name='Analysis by Destination Host')
    workbook = writer.book
    worksheet = writer.sheets['Analysis by Destination Host']
    worksheet.set_column('A:B', 18)
    worksheet.set_column('C:C', 70) 

#File Compression
#Get current path
path = os.getcwd()
os.chdir(path)
files = sorted(os.listdir(os.getcwd()), key=os.path.getmtime)

#Get newst file
newest = files[-1]
newest_file_path=os.getcwd() + '/' + newest

if __name__ == '__main__':
    single_file = newest_file_path
    
    with ZipFile('SOC_suricata_report' + ' ' + start_remove_output +  ' ' + 'to'+ ' ' +  end_remove_csv_output +  '.zip', mode='w') as zf:
        zf.write(single_file)

# with open(newest_file_path, 'rb') as f_in:
#     with gzip.open('SOC_suricata_report.zip', 'wb') as f_out:
#         shutil.copyfileobj(f_in, f_out)

#Write dataframe to csv and compress to zip
#compression_opts = dict(method='zip',  archive_name="suricata.csv")
#df7.to_csv('SOC_suricata_report' + ' ' + start_remove_output +  ' ' + 'to'+ ' ' +  end_remove_csv_output +  '.zip', index=False, compression=compression_opts)

#Gracefully exit
sys.exit()
