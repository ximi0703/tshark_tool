#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: wireShackTest.py
# Date: 2024/7/23
# Author: chuanwen.peng
import json
import logging
import os
import re
import struct
import subprocess
import threading
import time
from datetime import datetime
from multiprocessing import Process
import psutil
import pyshark
import yaml

# 创建日志记录器
logger = logging.getLogger('my_logger')
logger.setLevel(logging.INFO)

# 创建文件处理器
file_handler = logging.FileHandler('my_log.log')

# 设置日志格式
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# 创建控制台处理器并设置日志格式
console_handler = logging.StreamHandler()
console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# 添加处理器到日志记录器
logger.addHandler(file_handler)
logger.addHandler(console_handler)


class GetShackData:
    def __init__(self, pcap_file_path):
        self.cap = pyshark.FileCapture(pcap_file_path, display_filter='tcp')

    def hex_to_json(self, hex_str, indent=2):
        """
        将十六进制字符串转换为格式化的 JSON 字符串。

        Args:
            hex_str (str): 十六进制字符串。
            indent (int, optional): JSON 缩进空格数,默认为 2。

        Returns:
            str: 格式化的 JSON 字符串。
        """
        # 将十六进制字符串转换为字节数组
        byte_data = bytes.fromhex(hex_str)

        # 尝试解析字节数组中的 JSON 数据
        try:
            all_data_list = byte_data.decode('utf-8').split("\x00")
            json_data_list = [json.loads(i) for i in all_data_list]
            # return json.dumps(json_data, indent=indent)
            return json_data_list[0]
        except (UnicodeDecodeError, json.JSONDecodeError):
            # 如果无法直接解码为 JSON,尝试逐个字节解析
            json_data = {}
            current_key = None
            current_value = []
            for byte in byte_data:
                char = chr(byte)
                if char == '"':
                    if current_key is None:
                        current_key = ''.join(current_value)
                        current_value = []
                    else:
                        json_data[current_key] = ''.join(current_value)
                        current_key = None
                        current_value = []
                else:
                    current_value.append(char)
            if current_key is not None:
                json_data[current_key] = ''.join(current_value)
            return json.dumps(json_data, indent=indent)

    def write_to_file(self, message_dist, output_file):
        with open(output_file, 'a+') as f:
            json.dump(message_dist, f, indent=4)
            f.write('\n')

    def process_register(self, tab_reg):
        tab_reg = [int(i, 16) for i in tab_reg]
        hex_num1 = hex(tab_reg[0])[2:]
        hex_num2 = hex(tab_reg[1])[2:]
        float_num = hex_num1 + hex_num2
        dec_num = int(float_num, 16)
        f_vlaue = struct.unpack('f', struct.pack('I', dec_num))[0]
        # f_res = round(f_vlaue, 2)
        return f_vlaue

    def write_tcp_to_file(self, lines, output_file):
        with open(output_file, 'a+') as f:
            f.writelines(lines)
            f.write('\n')

    def process_packets(self, port_list, message_file_name):
        for packet in self.cap:
            if hasattr(packet, "tcp"):
                if "127.0.0.1" in packet.ip.addr and packet.tcp.flags == '0x0018' and int(
                        packet.captured_length) > 98 and (
                        port_list["service"] == int(packet.tcp.dstport) or port_list["ui"] == int(packet.tcp.dstport)):
                    # 解析本地通信消息ui和service
                    row_data_first = packet.tcp.get_field_value('payload').replace(":", ' ')
                    if "7b" in row_data_first:
                        row_data_new = row_data_first[row_data_first.find("7b"):]
                        ui_message = self.hex_to_json(re.sub("7d 00.*?7b", '7d 00 7b', row_data_new))
                        who_send = "ui" if int(packet.tcp.dstport) == port_list["ui"] else "service"
                        logger.info("who_send: %s, message_type: %s, message_para: %s" % (
                            who_send, ui_message.get("message_type"), ui_message.get("message_para")))
                    else:
                        logger.error("数据有误，找不到{")
                elif (port_list["robot"] == int(packet.tcp.dstport) or port_list[
                    "robot"] == int(packet.tcp.srcport)) and packet.tcp.flags == '0x0018' and hasattr(packet, "data"):
                    # 解析keba和service
                    row_data = packet.data.data
                    send_message = bytes.fromhex(row_data).decode("utf-8")
                    who_send = "service" if int(packet.tcp.dstport) == port_list["robot"] else "keba"
                    logger.info("who_send: %s, message: %s" % (who_send, send_message))
                elif "192.168.0.20" in packet.ip.addr and [i for i in packet.layers if
                                                           "modbus" in i.layer_name.lower()]:
                    # 解析plc和service
                    if int(packet.tcp.dstport) == port_list["plc"]:
                        # 发送给设备指令
                        row_data = packet.tcp.get_field_value('payload').replace(":", ' ')
                        row_data_new = row_data[18:]
                        print("当前帧号：%s" % packet.number)
                        print("send message: %s" % row_data_new)
                    elif int(packet.tcp.srcport) == port_list["plc"]:
                        # 接收指令
                        row_data = packet.tcp.get_field_value('payload').replace(":", ' ')
                        # 截取数据位
                        row_data_new = row_data[27:]
                        ret_data = ["".join(row_data_new.split()[:2]), "".join(row_data_new.split()[2:])]
                        res_data = self.process_register(ret_data)
                        print("响应帧号：%s" % packet.modbus.request_frame)
                        print("receive message: %s" % res_data)
                elif packet.tcp.flags == '0x0018' and int(packet.captured_length) > 98 and (
                        port_list["tcp"][0] == int(packet.tcp.dstport) or port_list["tcp"][1] == int(
                    packet.tcp.dstport)):
                    # tcp_cur_time = packet.sniff_timestamp
                    tcp_message = bytes.fromhex(packet.data.data).decode('utf-8')
                    lines = packet.frame_info.time_relative + "," + tcp_message.replace(";", '')
                    # lines = tcp_cur_time + "," + tcp_message.replace(";", '')
                    # logger.info(lines)
                    self.write_tcp_to_file(lines, "tcp_message_2000.txt")
            else:
                logger.error("没有tcp属性")


def load_cfg():
    with open('cfg.yaml', 'r', encoding='utf-8') as f:
        con = f.read()
    cfg = yaml.safe_load(con)
    # logger.info(cfg['tshark_path'])
    return cfg


class CapturePackets:
    def __init__(self, process_name="UpperComputerSoftware.exe"):
        self.process_name = process_name
        self.all_shack = []
        self.cfg = load_cfg()
        self.get_all_shack()

    # 检查进程是否在运行
    def is_process_running(self):
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == self.process_name:
                return True
        return False

    def build_filter_ports(self, port_list):
        filter_string = ''
        for port in port_list:
            if not filter_string:
                filter_string = "dst port %s" % port
            else:
                if not isinstance(port, list):
                    filter_string += " or dst port %s" % port
                else:
                    for p in port:
                        filter_string += " or dst port %s" % p
        return filter_string

    def capture_packets(self, filter_condition, port_list, output_file, process_name):
        if isinstance(filter_condition, list):
            ports = self.build_filter_ports(port_list)
            command = 'tshark -i %s -i %s -f "%s" -w %s' % (
                filter_condition[0], filter_condition[1], ports, output_file)
            # command = 'tshark -i %s -i %s -f "%s" -w -' % (filter_condition[0], filter_condition[1], ports)
        else:
            ports = self.build_filter_ports(port_list)
            command = 'tshark -i %s -f "%s" -w %s' % (filter_condition, ports, output_file)
        logger.info(command)
        tshark_proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True)
        time.sleep(10)
        if not self.is_process_running():
            time.sleep(10)
        while True:
            while self.is_process_running():
                time.sleep(3)
            else:
                tshark_proc.terminate()
                self.stop_tshark()
                break

    # 停止 tshark 捕获
    def stop_tshark(self):
        os.system("taskkill /f /im TShark.exe")
        logger.info(f"Stopped tshark capture for {self.process_name}")

    def get_all_shack(self):
        proc = subprocess.Popen(["tshark", "-D"], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        self.all_shack = [i.decode('utf-8') for i in proc.stdout.readlines()]

    def capture_data(self):
        pcapng_file_path = os.path.join(os.getcwd(), "pcapng_output")
        if not os.path.exists(pcapng_file_path):
            os.makedirs(pcapng_file_path)
        file_time = datetime.now().strftime("%m_%d_%H_%M")

        # tshark_path = cfg.get("tshark_path")
        port_list = self.cfg.get("port")
        local_host_li = [port_list[port] for port in port_list if
                         "ui" in port or "service" in port or "huahang" in port]
        ethernet_host_li = [port_list[port] for port in port_list if "robot" in port or "plc" in port]
        if local_host_li and ethernet_host_li:
            # 多进程共同抓取
            file_name = os.path.join(pcapng_file_path, 'localhost_capture_%s.pcap' % file_time)
            shack_type_list = [i for i in self.all_shack if "loopback" in i or "以太网" in i]
            shack_type = [i.split(".")[0] for i in shack_type_list]
            self.capture_packets(shack_type, list(port_list.values()), file_name, self.process_name)
        else:
            if local_host_li:
                file_name = os.path.join(pcapng_file_path, 'localhost_capture_%s.pcap' % file_time)
                shack_type = [i for i in self.all_shack if "loopback" in i][0].split(".")[0]
                logger.info(shack_type)
                self.capture_packets(shack_type, local_host_li, file_name, self.process_name)
            if ethernet_host_li:
                file_name = os.path.join(pcapng_file_path, 'ethernet_capture_%s.pcap' % file_time)
                shack_type = [i for i in self.all_shack if "以太网" in i][0].split(".")[0]
                logger.info(shack_type)
                self.capture_packets(shack_type, local_host_li, file_name, self.process_name)
            else:
                logger.info("没有需要捕获的网卡")
                return False

        # 分析数据
        get_data = GetShackData(file_name)
        get_data.process_packets(port_list, os.path.join(pcapng_file_path, 'message_%s.json' % file_time))


if __name__ == '__main__':
    # 实时监控
    # cap = CapturePackets()
    # cap.capture_data()

    # 分析抓包数据
    get_data = GetShackData(r"pcapng_output/localhost_capture_07_30_17_05.pcap")
    cfg = load_cfg()
    get_data.process_packets(cfg.get("port"), 'message_%s.json')
