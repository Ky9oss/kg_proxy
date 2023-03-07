import sys
import socket
import textwrap
import threading
import re





    





def start_listen(proxy_ip, proxy_port, server_ip, server_port, first_receive, filename):

    # create socket
    socket_to_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # connect client
    socket_to_client.bind((proxy_ip, proxy_port))
    socket_to_client.listen(5)

    while True:
        real_client, real_client_address = socket_to_client.accept()
        print(f'[*] 已连接client： {real_client_address[0]}:{real_client_address[1]}')

        new_thread = threading.Thread(target=main_loop, args=(real_client, real_client_address, server_ip, server_port, first_receive, filename))
        new_thread.start()
    


def main_loop(real_client, real_client_address, server_ip, server_port, first_receive, filename):

    if 'None' in filename:
        pass
    else:
        #覆盖旧数据
        with open(filename, 'w') as f:
            f.write('<记录经过TCP代理的数据>\n')

    #create socket
    socket_to_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #connect server
    try:
        socket_to_server.settimeout(5)
        socket_to_server.connect((server_ip, server_port))
        print(f'[*] 已连接server: {server_ip}:{server_port}')
    except TimeoutError:
        print('无法连接对方服务器')
        real_client.send(b'We can not connect to the server!\n')
        real_client.close()
        socket_to_server.close()
        sys.exit()


    #如果first_receive为True，先收一次服务端的数据,发给client
    if 'True' in first_receive:
        try:
            #settimeout:如果套接字堵塞超时，则报异常
            recvfs_all = b''
            while True:
                socket_to_server.settimeout(5)
                recvfs = socket_to_server.recv(4096)
                recvfs_all += recvfs
                if len(recvfs) < 4096:
                    break
            print(f'[*] Receive Package from Server--{server_ip}:{server_port}')

            sniff_print(recvfs_all)
            sniff_change_client()

            real_client.send(recvfs_all)
            print(f'[*] Send to Client--{real_client_address[0]}:{real_client_address[1]}')

        except TimeoutError as e:

            print(f'[!!] TIMEOUT: {e}')

        

    while True:

        '''
        handler是超时的回调函数
        count = 0
        def handler(signum, frame):
            print('[!!] TIMEOUT!')
            nonlocal count
            count += 1
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(5)
        xxx
        signal.alarm(0)
        看signal的官方文档说，signal.signal必须用于主线程的主解释器，否则会引发异常，没办法了，这次用settimeout()
        '''

        #计数器
        count = 0
        #server_count = 0

        #收client数据，发给server
        try:

            #settimeout:如果套接字堵塞超时，则报异常
            recvfc = b''
            recvfc_all = b''
            while True:
                real_client.settimeout(5)
                recvfc = real_client.recv(4096)
                recvfc_all += recvfc
                #if not recvfc: 
                #    break #不行，这样会一直recv，not recvfc只能在连接断开后触发
                if len(recvfc) < 4096:
                    break
            #对于python，当连接断开时，recv的结果为空
            if not recvfc_all:
                print('[!!] 代理与我方已断开连接')
                sys.exit() #count += 1 else:
            #print(f'[*] Receive Package from Client--{real_client_address[0]}:{real_client_address[1]}')

            else:
                print()
                print(f'[==>] Client to Server--{server_ip}:{server_port}')
                sniff_print(recvfc_all)
                print()
                sniff_change_client()

                socket_to_server.send(recvfc_all)

        except TimeoutError as e:

            print(f'[!!] Client TIMEOUT: {e}')
            count += 1


        #收server数据，发给client
        try:

            #settimeout:如果套接字堵塞超时，则报异常
            recvfs = b''
            recvfs_all = b''
            while True:
                socket_to_server.settimeout(5)
                #注意: 在已经通信过的双方连接中断后，recv会返回空
                recvfs = socket_to_server.recv(4096)
                recvfs_all += recvfs
                #if not recvfs: 
                #    break
                if len(recvfs)< 4096:
                    break
                #elif not recvfs_all:
                #    break
            
            if not recvfs_all:
                print('[!!] 代理与远端已断开连接')
                sys.exit()#退出线程
            else:
                #print(f'[*] Receive Package from Server--{server_ip}:{server_port}')

                print()
                print(f'[<==] Server to Client--{real_client_address[0]}:{real_client_address[1]}')
                sniff_print(recvfs_all)
                print()
                sniff_change_client()

                real_client.send(recvfs_all)

        except TimeoutError as e:

            print(f'[!!] Server TIMEOUT: {e}')
            count += 1
            #server_count += 1


        if count == 2:
            print('[Bye] 双方都停止发包，连接自动关闭')
            sys.exit()
        else:
            try:
                socket_to_server.connect((server_ip, server_port))
            except OSError:
                pass
                #print("连接未断开")
            else:
                print("[*] 对方已将连接断开，猜测对方http报文中的connection选项为close！")
                #socket_to_server.close()
                #real_client.close()
                sys.exit()

    

def sniff_print(recv_all):
    #创建（256个可显示字符的）表
    #对于英文字符，ASCII和UTF-8是相同的
    table = ''.join([len(repr(chr(i)))==3 and chr(i) or '.' for i in range(256)])
    print_list = []

    for i in range(0, len(recv_all), 16):
        word_bytes = recv_all[i:i+16]
        try:
            word_str = word_bytes.decode()
            word_translate = word_str.translate(table)
            word_ASCII_list = []
            #word_hex = ' '.join([f'{ord(c)}' for c in word_str])
            for c in word_str: #会把各种人类不可见的存在于str中的字符都算作c
                word_ASCII_number_hex = f'{ord(c):02X}'
                word_ASCII_list.append(word_ASCII_number_hex)
            word_ASCII_string_hex = ' '.join(word_ASCII_list)
            line_number = f'{i:04X}'
            print_list.append(f'{line_number}  {word_ASCII_string_hex:<48}  {word_translate}')
        except UnicodeDecodeError:
            #存在无法解码的情况，比如gzip压缩后的数据在网络中传输，其position1为0x8b
            #word_str = str(word_bytes)
            #print_list.append('gzip skip')
            pass
        
    for line in print_list:
        print(line)

    #w是覆盖写入，a是追加
    if 'None' in filename:
        pass
    else:
        with open(filename, 'a') as f:
            #f.truncate(0) #清空文件
            for line in print_list:
                f.write(line + '\n')


def sniff_change_client():
    pass


def sniff_change_server():
    pass


def hostname_to_address(i1):
    pattern1 = re.compile(r'\d+\.\d+\.\d+\.\d+')
    m = pattern1.match(i1)
    # 如果输入的格式为ipv4号
    if m is not None:
        return i1
        #try:
        #    hostname = socket.gethostbyaddr(i1)
        #except:
        #    print("没有找到该ip的对应域名")
        #else:
        #    print('找到了该ip的对应域名为:'+hostname[0])
        #finally:
        #    print('已选择你要连接的目标：'+i1)
        #    print('-------------------------------')
        #    return i1
    # 如果输入的格式为域名
    else:
        try:
            hostnumber = socket.gethostbyname(i1)
        except:
            print(f"[!!] 无法找到{i1}的对应ip。请检查是否输入错误，或尝试输入目标ip代替域名。")
            sys.exit()
        else:
            print(f'{i1}: {hostnumber}')
            return hostnumber





if __name__ == '__main__':

    introduction = textwrap.dedent(
        '''
        Usage: kgproxy [proxy_ip] [proxy_port] [server_ip] [server_port] [first_receive] [filename]

        Details:
            [first_receive]: If the server will send "hello" first like FTP. Then you should set the arg "True". Else, set the arg "False"
            [proxy_ip] & [server_ip]: These can be ipv4 address or hostname. The hostname will be parsed to ipv4 address.
            [filename]: If you want to save the flow which was through the TCP proxy in a file, 'filename' should be your file path. Or if you don't want to save, this should be 'None' 
        '''
            )


    if len(sys.argv[1:]) != 6:
        print(introduction)
        sys.exit()

    print(textwrap.dedent(
    '''
    ██╗  ██╗██╗   ██╗ ██████╗  ██████╗ ███████╗███████╗
    ██║ ██╔╝╚██╗ ██╔╝██╔════╝ ██╔═══██╗██╔════╝██╔════╝
    █████╔╝  ╚████╔╝ ██║  ███╗██║   ██║███████╗███████╗
    ██╔═██╗   ╚██╔╝  ██║   ██║██║   ██║╚════██║╚════██║
    ██║  ██╗   ██║   ╚██████╔╝╚██████╔╝███████║███████║
    ╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝                                                                      
    '''))
    proxy_ip = hostname_to_address(sys.argv[1])
    proxy_port = int(sys.argv[2])
    server_ip = hostname_to_address(sys.argv[3])
    server_port = int(sys.argv[4])
    first_receive = sys.argv[5]
    filename = sys.argv[6]

    start_listen(proxy_ip, proxy_port, server_ip, server_port, first_receive, filename)
