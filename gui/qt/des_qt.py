import sys
import time
from PyQt5 import QtCore, QtGui, QtWidgets


class SDES:
    """
    S-DES算法实现类
    """

    # 置换盒定义
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
    EP = [4, 1, 2, 3, 2, 3, 4, 1]
    P4 = [2, 4, 3, 1]

    # S盒定义
    S0 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 0, 2]
    ]

    S1 = [
        [0, 1, 2, 3],
        [2, 3, 1, 0],
        [3, 0, 1, 2],
        [2, 1, 0, 3]
    ]

    @staticmethod
    def permute(bits, permutation):
        """执行置换操作"""
        return [bits[i - 1] for i in permutation]

    @staticmethod
    def left_shift(bits, n):
        """循环左移"""
        return bits[n:] + bits[:n]

    @staticmethod
    def xor(bits1, bits2):
        """异或操作"""
        return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

    @staticmethod
    def s_box_lookup(bits, s_box):
        """S盒查找"""
        row = (bits[0] << 1) + bits[1]
        col = (bits[2] << 1) + bits[3]
        value = s_box[row][col]
        return [value >> 1 & 1, value & 1]

    @staticmethod
    def string_to_bits(text):
        """将字符串转换为二进制位列表"""
        bits = []
        for char in text:
            byte = ord(char)
            bits.extend([(byte >> i) & 1 for i in range(7, -1, -1)])
        return bits

    @staticmethod
    def bits_to_string(bits):
        """将二进制位列表转换为字符串"""
        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i:i + 8]
            if len(byte) == 8:
                char_code = sum(bit << (7 - j) for j, bit in enumerate(byte))
                chars.append(chr(char_code))
        return ''.join(chars)

    @staticmethod
    def bits_to_hex(bits):
        """将二进制位列表转换为十六进制字符串"""
        result = ""
        for i in range(0, len(bits), 8):
            byte = bits[i:i + 8]
            if len(byte) == 8:
                value = sum(bit << (7 - j) for j, bit in enumerate(byte))
                result += f"{value:02X}"
        return result

    @staticmethod
    def hex_to_bits(hex_string):
        """将十六进制字符串转换为二进制位列表"""
        bits = []
        for i in range(0, len(hex_string), 2):
            byte_str = hex_string[i:i + 2]
            if len(byte_str) == 2:
                value = int(byte_str, 16)
                bits.extend([(value >> i) & 1 for i in range(7, -1, -1)])
        return bits

    def generate_keys(self, key):
        """生成子密钥k1和k2"""
        # P10置换
        p10_key = self.permute(key, self.P10)

        # 分割并左移
        left = p10_key[:5]
        right = p10_key[5:]

        # 第一次左移
        left_shift1_left = self.left_shift(left, 1)
        left_shift1_right = self.left_shift(right, 1)

        # 生成k1
        k1 = self.permute(left_shift1_left + left_shift1_right, self.P8)

        # 第二次左移
        left_shift2_left = self.left_shift(left_shift1_left, 2)
        left_shift2_right = self.left_shift(left_shift1_right, 2)

        # 生成k2
        k2 = self.permute(left_shift2_left + left_shift2_right, self.P8)

        return k1, k2

    def f_function(self, right, key):
        """轮函数F"""
        # 扩展置换
        expanded = self.permute(right, self.EP)

        # 与密钥异或
        xor_result = self.xor(expanded, key)

        # S盒替换
        s0_input = xor_result[:4]
        s1_input = xor_result[4:]

        s0_output = self.s_box_lookup(s0_input, self.S0)
        s1_output = self.s_box_lookup(s1_input, self.S1)

        # P4置换
        p4_result = self.permute(s0_output + s1_output, self.P4)

        return p4_result

    def encrypt_block(self, plaintext, key):
        """加密一个8位分组"""
        # 生成子密钥
        k1, k2 = self.generate_keys(key)

        # 初始置换
        ip_result = self.permute(plaintext, self.IP)

        # 第一轮
        left = ip_result[:4]
        right = ip_result[4:]
        f_result = self.f_function(right, k1)
        new_right = self.xor(left, f_result)

        # 交换
        left, right = right, new_right

        # 第二轮
        f_result = self.f_function(right, k2)
        new_left = self.xor(left, f_result)

        # 最终置换
        ciphertext = self.permute(new_left + right, self.IP_INV)

        return ciphertext

    def decrypt_block(self, ciphertext, key):
        """解密一个8位分组"""
        # 生成子密钥
        k1, k2 = self.generate_keys(key)

        # 初始置换
        ip_result = self.permute(ciphertext, self.IP)

        # 第一轮
        left = ip_result[:4]
        right = ip_result[4:]
        f_result = self.f_function(right, k2)
        new_right = self.xor(left, f_result)

        # 交换
        left, right = right, new_right

        # 第二轮
        f_result = self.f_function(right, k1)
        new_left = self.xor(left, f_result)

        # 最终置换
        plaintext = self.permute(new_left + right, self.IP_INV)

        return plaintext

    def encrypt(self, plaintext_bits, key):
        """加密数据"""
        # 确保数据是8位的倍数
        if len(plaintext_bits) % 8 != 0:
            padding = 8 - (len(plaintext_bits) % 8)
            plaintext_bits.extend([0] * padding)

        ciphertext_bits = []
        for i in range(0, len(plaintext_bits), 8):
            block = plaintext_bits[i:i + 8]
            encrypted_block = self.encrypt_block(block, key)
            ciphertext_bits.extend(encrypted_block)

        return ciphertext_bits

    def decrypt(self, ciphertext_bits, key):
        """解密数据"""
        plaintext_bits = []
        for i in range(0, len(ciphertext_bits), 8):
            block = ciphertext_bits[i:i + 8]
            decrypted_block = self.decrypt_block(block, key)
            plaintext_bits.extend(decrypted_block)

        return plaintext_bits


class BruteForceWorker(QtCore.QObject):
    progressChanged = QtCore.pyqtSignal(int)
    messageAppended = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal()

    def __init__(self, sdes, plaintext_str, ciphertext_str):
        super().__init__()
        self._sdes = sdes
        self._plaintext_str = plaintext_str
        self._ciphertext_str = ciphertext_str
        self._running = True

    @QtCore.pyqtSlot()
    def run(self):
        try:
            if len(self._plaintext_str) != 8 or not all(bit in '01' for bit in self._plaintext_str):
                self.messageAppended.emit("错误: 明文必须是8位二进制数\n")
                return
            if len(self._ciphertext_str) != 8 or not all(bit in '01' for bit in self._ciphertext_str):
                self.messageAppended.emit("错误: 密文必须是8位二进制数\n")
                return

            plaintext = [int(bit) for bit in self._plaintext_str]
            target_ciphertext = [int(bit) for bit in self._ciphertext_str]

            start_time = time.time()
            found_count = 0

            for key_int in range(1024):
                if not self._running:
                    break
                key = [(key_int >> i) & 1 for i in range(9, -1, -1)]
                try:
                    encrypted = self._sdes.encrypt_block(plaintext, key)
                    if encrypted == target_ciphertext:
                        key_str = ''.join(str(bit) for bit in key)
                        self.messageAppended.emit(f"找到密钥: {key_str}\n")
                        found_count += 1
                except Exception:
                    pass
                self.progressChanged.emit(key_int + 1)

            elapsed_time = time.time() - start_time
            self.messageAppended.emit(f"\n破解完成! 用时: {elapsed_time:.2f}秒\n")
            if found_count:
                self.messageAppended.emit(f"共找到 {found_count} 个可能的密钥\n")
            else:
                self.messageAppended.emit("未找到匹配的密钥\n")
        finally:
            self.finished.emit()

    def stop(self):
        self._running = False


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("S-DES 加解密系统 (PyQt)")
        self.resize(900, 720)
        self.sdes = SDES()
        self._current_theme = "light"

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QVBoxLayout(central)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        self.tabs = QtWidgets.QTabWidget()
        layout.addWidget(self.tabs)

        self._init_basic_tab()
        self._init_extend_tab()
        self._init_bruteforce_tab()
        self._init_analysis_tab()

        self._create_toolbar()

        self.statusBar().showMessage("就绪")

        self._brute_thread = None
        self._brute_worker = None

    def _apply_card(self, widget: QtWidgets.QWidget) -> QtWidgets.QWidget:
        frame = QtWidgets.QFrame()
        frame.setObjectName("Card")
        layout = QtWidgets.QVBoxLayout(frame)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)
        layout.addWidget(widget)
        shadow = QtWidgets.QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(24)
        shadow.setXOffset(0)
        shadow.setYOffset(8)
        shadow.setColor(QtGui.QColor(0, 0, 0, 40))
        frame.setGraphicsEffect(shadow)
        return frame

    def _init_basic_tab(self):
        tab = QtWidgets.QWidget()
        outer = QtWidgets.QVBoxLayout(tab)
        outer.setContentsMargins(4, 12, 4, 12)
        form_host = QtWidgets.QWidget()
        form = QtWidgets.QGridLayout(form_host)
        form.setContentsMargins(16, 16, 16, 16)
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)

        form.addWidget(QtWidgets.QLabel("10位密钥 (二进制):"), 0, 0)
        self.key_entry = QtWidgets.QLineEdit()
        self.key_entry.setPlaceholderText("例如: 1010000010")
        form.addWidget(self.key_entry, 0, 1)

        form.addWidget(QtWidgets.QLabel("8位明文 (二进制):"), 1, 0)
        self.plaintext_entry = QtWidgets.QLineEdit()
        self.plaintext_entry.setPlaceholderText("例如: 01110010")
        form.addWidget(self.plaintext_entry, 1, 1)

        encrypt_btn = QtWidgets.QPushButton("加密")
        encrypt_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_DialogApplyButton))
        encrypt_btn.clicked.connect(self.encrypt_basic)
        form.addWidget(encrypt_btn, 2, 0)

        decrypt_btn = QtWidgets.QPushButton("解密")
        decrypt_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_BrowserReload))
        decrypt_btn.clicked.connect(self.decrypt_basic)
        form.addWidget(decrypt_btn, 2, 1)

        form.addWidget(QtWidgets.QLabel("结果:"), 3, 0)
        self.result_text = QtWidgets.QPlainTextEdit()
        self.result_text.setReadOnly(True)
        form.addWidget(self.result_text, 4, 0, 1, 2)

        example_btn = QtWidgets.QPushButton("填充示例")
        example_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_FileDialogInfoView))
        example_btn.clicked.connect(self.fill_example)
        form.addWidget(example_btn, 5, 0, 1, 2)

        outer.addWidget(self._apply_card(form_host))
        self.tabs.addTab(tab, "基本测试")

    def _init_extend_tab(self):
        tab = QtWidgets.QWidget()
        outer = QtWidgets.QVBoxLayout(tab)
        outer.setContentsMargins(4, 12, 4, 12)
        form_host = QtWidgets.QWidget()
        form = QtWidgets.QGridLayout(form_host)
        form.setContentsMargins(16, 16, 16, 16)
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)

        form.addWidget(QtWidgets.QLabel("10位密钥 (二进制):"), 0, 0)
        self.ext_key_entry = QtWidgets.QLineEdit()
        form.addWidget(self.ext_key_entry, 0, 1)

        form.addWidget(QtWidgets.QLabel("文本:"), 1, 0)
        self.text_entry = QtWidgets.QPlainTextEdit()
        form.addWidget(self.text_entry, 2, 0, 1, 2)

        encrypt_btn = QtWidgets.QPushButton("加密文本")
        encrypt_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_DialogApplyButton))
        encrypt_btn.clicked.connect(self.encrypt_text)
        form.addWidget(encrypt_btn, 3, 0)

        decrypt_btn = QtWidgets.QPushButton("解密文本")
        decrypt_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_BrowserReload))
        decrypt_btn.clicked.connect(self.decrypt_text)
        form.addWidget(decrypt_btn, 3, 1)

        form.addWidget(QtWidgets.QLabel("结果:"), 4, 0)
        self.ext_result_text = QtWidgets.QPlainTextEdit()
        self.ext_result_text.setReadOnly(True)
        form.addWidget(self.ext_result_text, 5, 0, 1, 2)

        outer.addWidget(self._apply_card(form_host))
        self.tabs.addTab(tab, "扩展功能")

    def _init_bruteforce_tab(self):
        tab = QtWidgets.QWidget()
        outer = QtWidgets.QVBoxLayout(tab)
        outer.setContentsMargins(4, 12, 4, 12)
        form_host = QtWidgets.QWidget()
        form = QtWidgets.QGridLayout(form_host)
        form.setContentsMargins(16, 16, 16, 16)
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)

        form.addWidget(QtWidgets.QLabel("已知明文 (二进制):"), 0, 0)
        self.known_plaintext = QtWidgets.QLineEdit()
        form.addWidget(self.known_plaintext, 0, 1)

        form.addWidget(QtWidgets.QLabel("已知密文 (二进制):"), 1, 0)
        self.known_ciphertext = QtWidgets.QLineEdit()
        form.addWidget(self.known_ciphertext, 1, 1)

        brute_btn = QtWidgets.QPushButton("开始暴力破解")
        brute_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_MediaPlay))
        brute_btn.clicked.connect(self.start_brute_force)
        form.addWidget(brute_btn, 2, 0)

        stop_btn = QtWidgets.QPushButton("停止破解")
        stop_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_MediaStop))
        stop_btn.clicked.connect(self.stop_brute_force)
        form.addWidget(stop_btn, 2, 1)

        form.addWidget(QtWidgets.QLabel("进度:"), 3, 0)
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setRange(0, 1024)
        form.addWidget(self.progress_bar, 3, 1)

        form.addWidget(QtWidgets.QLabel("破解结果:"), 4, 0)
        self.brute_result_text = QtWidgets.QPlainTextEdit()
        self.brute_result_text.setReadOnly(True)
        form.addWidget(self.brute_result_text, 5, 0, 1, 2)

        outer.addWidget(self._apply_card(form_host))
        self.tabs.addTab(tab, "暴力破解")

    def _init_analysis_tab(self):
        tab = QtWidgets.QWidget()
        outer = QtWidgets.QVBoxLayout(tab)
        outer.setContentsMargins(4, 12, 4, 12)
        host = QtWidgets.QWidget()
        vbox = QtWidgets.QVBoxLayout(host)
        vbox.setContentsMargins(16, 16, 16, 16)
        vbox.setSpacing(8)

        analyze_btn = QtWidgets.QPushButton("分析密钥冲突")
        analyze_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_FileDialogDetailedView))
        analyze_btn.clicked.connect(self.analyze_key_conflicts)
        vbox.addWidget(analyze_btn)

        self.analysis_text = QtWidgets.QPlainTextEdit()
        self.analysis_text.setReadOnly(True)
        vbox.addWidget(self.analysis_text)
        outer.addWidget(self._apply_card(host))
        self.tabs.addTab(tab, "封闭测试")

    def _create_toolbar(self):
        toolbar = QtWidgets.QToolBar("工具")
        toolbar.setMovable(False)
        toolbar.setIconSize(QtCore.QSize(18, 18))
        self.addToolBar(QtCore.Qt.TopToolBarArea, toolbar)

        act_theme = QtWidgets.QAction(self.style().standardIcon(QtWidgets.QStyle.SP_DesktopIcon), "切换主题", self)
        act_theme.setStatusTip("在明亮/暗色主题之间切换")
        act_theme.triggered.connect(self._toggle_theme)

        act_quit = QtWidgets.QAction(self.style().standardIcon(QtWidgets.QStyle.SP_DialogCloseButton), "退出", self)
        act_quit.triggered.connect(QtWidgets.qApp.quit)

        toolbar.addAction(act_theme)
        toolbar.addSeparator()
        toolbar.addAction(act_quit)

    def _toggle_theme(self):
        self._current_theme = "dark" if self._current_theme == "light" else "light"
        qss = "styles_dark.qss" if self._current_theme == "dark" else "styles.qss"
        load_qss(QtWidgets.qApp, qss)

    # 业务逻辑
    def fill_example(self):
        self.key_entry.setText("1010000010")
        self.plaintext_entry.setText("01110010")

    def encrypt_basic(self):
        key_str = self.key_entry.text().strip()
        plaintext_str = self.plaintext_entry.text().strip()
        if len(key_str) != 10 or not all(bit in '01' for bit in key_str):
            QtWidgets.QMessageBox.critical(self, "错误", "密钥必须是10位二进制数")
            return
        if len(plaintext_str) != 8 or not all(bit in '01' for bit in plaintext_str):
            QtWidgets.QMessageBox.critical(self, "错误", "明文必须是8位二进制数")
            return
        key = [int(bit) for bit in key_str]
        plaintext = [int(bit) for bit in plaintext_str]
        ciphertext = self.sdes.encrypt_block(plaintext, key)
        ciphertext_str = ''.join(str(bit) for bit in ciphertext)
        self.result_text.setPlainText(
            f"明文: {plaintext_str}\n密钥: {key_str}\n密文: {ciphertext_str}\n"
        )

    def decrypt_basic(self):
        key_str = self.key_entry.text().strip()
        ciphertext_str = self.plaintext_entry.text().strip()
        if len(key_str) != 10 or not all(bit in '01' for bit in key_str):
            QtWidgets.QMessageBox.critical(self, "错误", "密钥必须是10位二进制数")
            return
        if len(ciphertext_str) != 8 or not all(bit in '01' for bit in ciphertext_str):
            QtWidgets.QMessageBox.critical(self, "错误", "密文必须是8位二进制数")
            return
        key = [int(bit) for bit in key_str]
        ciphertext = [int(bit) for bit in ciphertext_str]
        plaintext = self.sdes.decrypt_block(ciphertext, key)
        plaintext_str = ''.join(str(bit) for bit in plaintext)
        self.result_text.setPlainText(
            f"密文: {ciphertext_str}\n密钥: {key_str}\n明文: {plaintext_str}\n"
        )

    def encrypt_text(self):
        key_str = self.ext_key_entry.text().strip()
        text = self.text_entry.toPlainText().strip()
        if len(key_str) != 10 or not all(bit in '01' for bit in key_str):
            QtWidgets.QMessageBox.critical(self, "错误", "密钥必须是10位二进制数")
            return
        key = [int(bit) for bit in key_str]
        text_bits = self.sdes.string_to_bits(text)
        ciphertext_bits = self.sdes.encrypt(text_bits, key)
        ciphertext_hex = self.sdes.bits_to_hex(ciphertext_bits)
        ciphertext_str = self.sdes.bits_to_string(ciphertext_bits)
        self.ext_result_text.setPlainText(
            f"原文: {text}\n密钥: {key_str}\n密文(十六进制): {ciphertext_hex}\n密文(字符串): {ciphertext_str}\n"
        )

    def decrypt_text(self):
        key_str = self.ext_key_entry.text().strip()
        text = self.text_entry.toPlainText().strip()
        if len(key_str) != 10 or not all(bit in '01' for bit in key_str):
            QtWidgets.QMessageBox.critical(self, "错误", "密钥必须是10位二进制数")
            return
        key = [int(bit) for bit in key_str]
        try:
            ciphertext_bits = self.sdes.hex_to_bits(text)
        except Exception:
            ciphertext_bits = self.sdes.string_to_bits(text)
        plaintext_bits = self.sdes.decrypt(ciphertext_bits, key)
        plaintext_str = self.sdes.bits_to_string(plaintext_bits)
        self.ext_result_text.setPlainText(
            f"密文: {text}\n密钥: {key_str}\n明文: {plaintext_str}\n"
        )

    def start_brute_force(self):
        if self._brute_thread is not None:
            QtWidgets.QMessageBox.warning(self, "警告", "暴力破解正在进行中")
            return
        self.brute_result_text.clear()
        self.progress_bar.setValue(0)
        plaintext = self.known_plaintext.text().strip()
        ciphertext = self.known_ciphertext.text().strip()

        self._brute_thread = QtCore.QThread(self)
        self._brute_worker = BruteForceWorker(self.sdes, plaintext, ciphertext)
        self._brute_worker.moveToThread(self._brute_thread)
        self._brute_thread.started.connect(self._brute_worker.run)
        self._brute_worker.progressChanged.connect(self.progress_bar.setValue)
        self._brute_worker.messageAppended.connect(lambda s: self.brute_result_text.appendPlainText(s.strip('\n')))
        self._brute_worker.finished.connect(self._on_brute_finished)
        self._brute_thread.start()
        self.statusBar().showMessage("暴力破解中...")

    def stop_brute_force(self):
        if self._brute_worker is not None:
            self._brute_worker.stop()

    def _on_brute_finished(self):
        try:
            if self._brute_thread is not None:
                self._brute_thread.quit()
                self._brute_thread.wait(2000)
        finally:
            self._brute_thread = None
            self._brute_worker = None
            self.statusBar().showMessage("就绪")

    def analyze_key_conflicts(self):
        import random
        self.analysis_text.clear()
        self.analysis_text.appendPlainText("开始分析密钥冲突...")
        test_plaintext = [random.randint(0, 1) for _ in range(8)]
        plaintext_str = ''.join(str(bit) for bit in test_plaintext)
        ciphertext_to_keys = {}
        key_conflicts = []
        start_time = time.time()
        for key_int in range(1024):
            key = [(key_int >> i) & 1 for i in range(9, -1, -1)]
            key_str = ''.join(str(bit) for bit in key)
            try:
                ciphertext = self.sdes.encrypt_block(test_plaintext, key)
                ciphertext_s = ''.join(str(bit) for bit in ciphertext)
                if ciphertext_s in ciphertext_to_keys:
                    existing_key = ciphertext_to_keys[ciphertext_s]
                    key_conflicts.append((existing_key, key_str, ciphertext_s))
                else:
                    ciphertext_to_keys[ciphertext_s] = key_str
            except Exception:
                pass
        elapsed_time = time.time() - start_time
        self.analysis_text.appendPlainText(f"\n分析完成! 用时: {elapsed_time:.2f}秒")
        self.analysis_text.appendPlainText(f"测试明文: {plaintext_str}")
        self.analysis_text.appendPlainText(f"不同密文数量: {len(ciphertext_to_keys)}")
        self.analysis_text.appendPlainText(f"密钥冲突数量: {len(key_conflicts)}\n")
        if key_conflicts:
            self.analysis_text.appendPlainText("发现的密钥冲突:")
            for i, (key1, key2, ciphertext) in enumerate(key_conflicts[:10]):
                self.analysis_text.appendPlainText(
                    f"冲突 {i + 1}: 密钥 {key1} 和 {key2} 产生相同密文 {ciphertext}"
                )
            if len(key_conflicts) > 10:
                self.analysis_text.appendPlainText(
                    f"... 还有 {len(key_conflicts) - 10} 个冲突未显示"
                )
        else:
            self.analysis_text.appendPlainText("未发现密钥冲突")


def load_qss(app: QtWidgets.QApplication, qss_path: str = "styles.qss") -> None:
    try:
        with open(qss_path, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())
    except Exception:
        pass


def main():
    QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)
    QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps, True)
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QtGui.QFont("Microsoft YaHei UI", 10))
    load_qss(app)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()