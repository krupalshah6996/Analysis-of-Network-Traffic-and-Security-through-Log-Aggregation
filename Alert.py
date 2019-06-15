import threading
import pygeoip

def func():
	try:
		#import threading
		out=open("/home/krupal/Downloads/ip_count.txt",'w')
		rawdata=pygeoip.GeoIP('/home/krupal/Downloads/GeoLiteCity.dat')
		def ipquery(ip):
			try:
				data=rawdata.record_by_name(ip)
				country=data['country_name']
				return str(country)
			except:
				pass
	
		def refine():
			try:
		
				f=open('/home/krupal/Downloads/log.txt','r').readlines()
				#f=open('/var/log/firewalls/10.10.12.1/2018/03/10.10.12.1-2018-03-27.log','r').readlines()
				opt=open('/home/krupal/Downloads/opt.csv','w')
		
				def parse(line):
					try:
						line = line.split(',')
						line[0] = line[0].split()
						line[0] = line[0][:4] + line[0][5:]
		
						string = "%s %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" % (line[0][0], line[0][1], line[0][2],line[0][3],(line[0][4]),(line[3]),line[4],line[5],line[6],line[7],(line[8]),line[9],(line[11]),(line[12]),(line[13]),line[14],(line[15]),line[16],(line[17]),line[18],line[19],(line[20]),(line[21]))
						opt.write(string)
				
					except:	
						pass
	
				str = "date,time,hostname,rulenumber,tid,realinterface,reason,action,direction,version,tos,ttl,id,offset,flags,pid,protocol,length,sourceip,destip,srcport,destport\n"		
				opt.write(str)
				for line in f:
					parse(line)
				opt.close()
	
				print("sd")
			except:
				pass
		def ids():
			try:
				print("ids strt")
				f=open("/home/krupal/Downloads/ips.log",'r').readlines()
				opt1=open("/home/krupal/Downloads/ipsconv.log",'r').readlines()
				opt2=open("/home/krupal/Downloads/ipsconv.log",'w')
				ips=open("/home/krupal/Downloads/ips.csv",'w')
				#mal=open("/home/krupal/Downloads/ips.csv",'r').readlines()
				#mal_ip=open("/home/krupal/Downloads/malicious_ips.txt",'w')
		
				str1="suricata"
				str2="snort"
				str3='Classification'
				str4='[Priority'
				end1=0
				end2=0
		
				def parse(line):
					try:
						line=line.split()
						#print(line)
						if str1 in line[4] or str2 in line[4]:
							string=' '.join(line)
							string=string+'\n'
							opt2.write(string)
				
					except:
						pass
				def extract(line):
					try:
						line=line.split()
						line[4]=line[4].split('[')
						#print(line)
						for word in line:
							if str3 in word:
								end1=line.index(word)
							if str4 in word:
								end2=line.index(word)
						string="%s %s %s,%s,%s,%s,%s,%s,%s\n" % (line[0],line[1],line[2],line[3],line[4][0],(' '.join(line[6:end1])),(' '.join(line[end1:end2])),line[-3],line[-1])
						ips.write(string)
					except:
						pass
				for line in f:
					parse(line)
				opt2.close()
				str = "timestamp,ip,type,message,classification,source_ip,destination_ip\n"
				ips.write(str)
				for line in opt1:
					extract(line)
				ips.close()
				#f.close()
				#opt1.close()
				print("sdsdf")
			except:
				pass
		def apache():
			try:
				print("apache strt")
				test=open("/home/krupal/Downloads/apache_test.log",'r').readlines()
				action=open("/home/krupal/Downloads/opt.csv",'r').readlines()
	

				dir1,dir2,dir3,dir4,dir5,dir6,dir7,dir8='/boot','/dev','/etc','/lib','/proc/sys','/root','/bin','/sbin'
				d_count=dict()
				status=dict()
				src_ip=dict()
				def convert(line):
					try:
	
						line=line.split()
						if 'GET' in line[5]:
							if dir1 in line[6] or dir2 in line[6] or dir3 in line[6] or dir4 in line[6] or dir5 in line[6] or dir6 in line[6] or dir7 in line[6] or dir8 in line[6]:
								if line[0] in d_count:
									d_count[line[0]]=d_count[line[0]]+1
								else:
									d_count[line[0]]=1
			
						if (int(line[8]))>=400:
							tup=(line[0],int(line[8]))
							status[tup]=status.get(tup,0)+1
					except:
						pass
	
				def match(line):
					try:
						line=line.split(',')
						#print(line)
						if 'block' in line[7]:
							if line[19] in src_ip:
								src_ip[line[19]]=src_ip[line[19]]+1
							else:
								src_ip[line[19]]=1
					except:
						pass
	
	
				for line in test:
					convert(line)
	
				for line in action:
					match(line)
	
				for x in d_count:
					if d_count[x]>5:
						string="%s %s %s\n" % (x,"accessing system file ",ipquery(x))
						out.write(string)
						#print(string)
	
				for x in status:
					if status[x]>5:
						string="%s %s %s\n" % (x[0],"status code violation",ipquery(x[0]))
						out.write(string)
						#print(string)
				for x in src_ip:
					if src_ip[x]>20:
						string="%s %s %s\n" % (x,"continous blocking",ipquery(x))
						out.write(string)
				print("apache close")
				#out.close()
			except:
				pass

		def mal():
			try:
				print("mal open")
				inp=open("/home/krupal/Downloads/ips.csv",'r').readlines()
				mal_ip=open("/home/krupal/Downloads/malicious_ips.txt",'w')
				#ip_count=open("/home/krupal/Downloads/ip_count.txt",'w')
				d=dict()
				attack=[]
				str1="Attack"
				str2="Bad"
				def detect(line):
					try:
						line=line.split(',')
						line[6]=line[6].rstrip('\n')
						temp=line[5][:line[5].rindex(':')]
						temp2=line[6][:line[6].rindex(':')]
						tup=(temp,temp2)
						#tup=(line[5],line[6])
						d[tup]=d.get(tup,0)+1
			
						if str1 in line[4] or str2 in line[4]:
							#index=line[5].rindex(':')
							#temp=line[5][:index]
							temp=line[5][:line[5].rindex(':')]
							if temp not in attack:
								attack.append(temp)
					except:
						pass
	
				for line in inp:
					detect(line)
				for key,value in d.items():
					string="%s %d\n" % (key,value)
					mal_ip.write(string)
				for x in d:
					if d[x]>10:
						string="%s %d %s\n" % (x[0],d[x],ipquery(x))
						out.write(string)
				for x in attack:
					string="%s %s %s\n" % (x,"attack",ipquery(x))
					out.write(string)
				print("mal end")
			except:
				pass	

	
		refine()
		ids()
		apache()
		mal()
		out.close()
		#t1=threading.Timer(1,refine)
		#t2=threading.Timer(3,ids)
		#t3=threading.Timer(5,apache)
		#t4=threading.Timer(8,mal)
		#t1.start()
		#t2.start()
		#t3.start()
		#t4.start()
		t=threading.Timer(5,func).start()
		#t.start()
		
	except:
		pass
func()
#t=threading.Timer(5,func).start()
#t.start()
