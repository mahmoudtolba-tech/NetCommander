"""
Main GUI Window
Modern interface for network automation
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
from typing import List
import os

from ..core.ip_validator import IPValidator
from ..core.connectivity import ConnectivityChecker
from ..core.ssh_handler import SSHHandler, SSHCredentials, SSHResult
from ..utils.config_manager import ConfigManager, Profile
from ..utils.logger import AutomationLogger, ReportGenerator
from ..utils.template_manager import TemplateManager, HistoryManager


class AutomationNetGUI:
    """Main GUI application"""

    def __init__(self, root):
        """Initialize GUI"""
        self.root = root
        self.root.title("AutomationNet - Network Device Automation Tool")
        self.root.geometry("1200x800")

        # Initialize managers
        self.config_manager = ConfigManager()
        self.template_manager = TemplateManager()
        self.history_manager = HistoryManager()
        self.logger = AutomationLogger()

        # GUI state
        self.ip_list = []
        self.command_list = []
        self.execution_results = []
        self.progress_queue = queue.Queue()

        # Create UI
        self.create_menu()
        self.create_widgets()

        # Start progress checker
        self.check_progress()

    def create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Profile", command=self.new_profile)
        file_menu.add_command(label="Save Profile", command=self.save_profile)
        file_menu.add_command(label="Load Profile", command=self.load_profile)
        file_menu.add_separator()
        file_menu.add_command(label="Export Report", command=self.export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Templates", command=self.show_templates)
        tools_menu.add_command(label="History", command=self.show_history)
        tools_menu.add_command(label="Settings", command=self.show_settings)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def create_widgets(self):
        """Create main widgets"""
        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create tabs
        self.create_setup_tab()
        self.create_execution_tab()
        self.create_results_tab()

    def create_setup_tab(self):
        """Create setup/configuration tab"""
        setup_frame = ttk.Frame(self.notebook)
        self.notebook.add(setup_frame, text="Setup")

        # Left panel - IP Configuration
        left_panel = ttk.LabelFrame(setup_frame, text="IP Configuration", padding=10)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # IP input method
        ttk.Label(left_panel, text="Input Method:").pack(anchor=tk.W)
        method_frame = ttk.Frame(left_panel)
        method_frame.pack(fill=tk.X, pady=5)

        self.ip_method = tk.StringVar(value="manual")
        ttk.Radiobutton(method_frame, text="Manual Entry", variable=self.ip_method,
                       value="manual", command=self.update_ip_input).pack(side=tk.LEFT)
        ttk.Radiobutton(method_frame, text="From File", variable=self.ip_method,
                       value="file", command=self.update_ip_input).pack(side=tk.LEFT)

        # Manual IP entry
        self.manual_ip_frame = ttk.Frame(left_panel)
        self.manual_ip_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        ttk.Label(self.manual_ip_frame, text="IP Addresses (one per line or CIDR):").pack(anchor=tk.W)
        self.ip_text = scrolledtext.ScrolledText(self.manual_ip_frame, height=10)
        self.ip_text.pack(fill=tk.BOTH, expand=True)

        # File IP entry
        self.file_ip_frame = ttk.Frame(left_panel)

        ttk.Label(self.file_ip_frame, text="IP File:").pack(anchor=tk.W)
        file_frame = ttk.Frame(self.file_ip_frame)
        file_frame.pack(fill=tk.X)
        self.ip_file_entry = ttk.Entry(file_frame)
        self.ip_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(file_frame, text="Browse", command=self.browse_ip_file).pack(side=tk.LEFT, padx=5)

        # Validate IPs button
        ttk.Button(left_panel, text="Validate IPs", command=self.validate_ips).pack(pady=5)

        # IP status
        self.ip_status = scrolledtext.ScrolledText(left_panel, height=5, state=tk.DISABLED)
        self.ip_status.pack(fill=tk.BOTH, expand=True, pady=5)

        # Right panel - Credentials & Commands
        right_panel = ttk.Frame(setup_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Credentials
        cred_frame = ttk.LabelFrame(right_panel, text="SSH Credentials", padding=10)
        cred_frame.pack(fill=tk.X, pady=5)

        ttk.Label(cred_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.username_entry = ttk.Entry(cred_frame)
        self.username_entry.grid(row=0, column=1, sticky=tk.EW, pady=2)

        ttk.Label(cred_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.password_entry = ttk.Entry(cred_frame, show="*")
        self.password_entry.grid(row=1, column=1, sticky=tk.EW, pady=2)

        ttk.Label(cred_frame, text="Enable Password:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.enable_password_entry = ttk.Entry(cred_frame, show="*")
        self.enable_password_entry.grid(row=2, column=1, sticky=tk.EW, pady=2)

        ttk.Label(cred_frame, text="Port:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.port_entry = ttk.Entry(cred_frame)
        self.port_entry.insert(0, "22")
        self.port_entry.grid(row=3, column=1, sticky=tk.EW, pady=2)

        cred_frame.columnconfigure(1, weight=1)

        # Commands
        cmd_frame = ttk.LabelFrame(right_panel, text="Commands", padding=10)
        cmd_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Template selection
        template_select_frame = ttk.Frame(cmd_frame)
        template_select_frame.pack(fill=tk.X, pady=5)

        ttk.Label(template_select_frame, text="Template:").pack(side=tk.LEFT)
        self.template_var = tk.StringVar()
        self.template_combo = ttk.Combobox(template_select_frame, textvariable=self.template_var, state="readonly")
        self.template_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.refresh_templates()
        self.template_combo.bind("<<ComboboxSelected>>", self.load_template_commands)

        ttk.Button(template_select_frame, text="Refresh", command=self.refresh_templates).pack(side=tk.LEFT)

        ttk.Label(cmd_frame, text="Commands (one per line):").pack(anchor=tk.W)
        self.commands_text = scrolledtext.ScrolledText(cmd_frame, height=15)
        self.commands_text.pack(fill=tk.BOTH, expand=True)

        # Bottom buttons
        button_frame = ttk.Frame(cmd_frame)
        button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Load from File", command=self.load_commands_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Save Template", command=self.save_template).pack(side=tk.LEFT, padx=2)

    def create_execution_tab(self):
        """Create execution tab"""
        exec_frame = ttk.Frame(self.notebook)
        self.notebook.add(exec_frame, text="Execution")

        # Settings panel
        settings_panel = ttk.LabelFrame(exec_frame, text="Execution Settings", padding=10)
        settings_panel.pack(fill=tk.X, padx=5, pady=5)

        # Ping check
        self.ping_check_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_panel, text="Ping devices before connecting",
                       variable=self.ping_check_var).grid(row=0, column=0, sticky=tk.W, pady=2)

        # Concurrent connections
        ttk.Label(settings_panel, text="Concurrent Connections:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.concurrent_spinbox = ttk.Spinbox(settings_panel, from_=1, to=20, width=10)
        self.concurrent_spinbox.set(5)
        self.concurrent_spinbox.grid(row=1, column=1, sticky=tk.W, pady=2)

        # Progress panel
        progress_panel = ttk.LabelFrame(exec_frame, text="Progress", padding=10)
        progress_panel.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_panel, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=5)

        # Status label
        self.status_label = ttk.Label(progress_panel, text="Ready")
        self.status_label.pack(anchor=tk.W)

        # Log output
        ttk.Label(progress_panel, text="Execution Log:").pack(anchor=tk.W)
        self.log_text = scrolledtext.ScrolledText(progress_panel, height=20, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Control buttons
        control_frame = ttk.Frame(exec_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        self.start_button = ttk.Button(control_frame, text="Start Execution", command=self.start_execution)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(control_frame, text="Stop", command=self.stop_execution, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        ttk.Button(control_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)

    def create_results_tab(self):
        """Create results tab"""
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="Results")

        # Summary panel
        summary_panel = ttk.LabelFrame(results_frame, text="Summary", padding=10)
        summary_panel.pack(fill=tk.X, padx=5, pady=5)

        self.total_label = ttk.Label(summary_panel, text="Total Devices: 0")
        self.total_label.grid(row=0, column=0, padx=10)

        self.success_label = ttk.Label(summary_panel, text="Successful: 0", foreground="green")
        self.success_label.grid(row=0, column=1, padx=10)

        self.failed_label = ttk.Label(summary_panel, text="Failed: 0", foreground="red")
        self.failed_label.grid(row=0, column=2, padx=10)

        # Results table
        table_frame = ttk.Frame(results_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Treeview for results
        columns = ("IP", "Status", "Time", "Error")
        self.results_tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=150)

        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_tree.config(yscrollcommand=scrollbar.set)

        # Bind double-click to show details
        self.results_tree.bind("<Double-1>", self.show_result_details)

        # Export buttons
        export_frame = ttk.Frame(results_frame)
        export_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(export_frame, text="Export Results:").pack(side=tk.LEFT, padx=5)
        ttk.Button(export_frame, text="Text", command=lambda: self.export_results("text")).pack(side=tk.LEFT, padx=2)
        ttk.Button(export_frame, text="CSV", command=lambda: self.export_results("csv")).pack(side=tk.LEFT, padx=2)
        ttk.Button(export_frame, text="JSON", command=lambda: self.export_results("json")).pack(side=tk.LEFT, padx=2)
        ttk.Button(export_frame, text="HTML", command=lambda: self.export_results("html")).pack(side=tk.LEFT, padx=2)

    # Event handlers
    def update_ip_input(self):
        """Update IP input method"""
        if self.ip_method.get() == "manual":
            self.file_ip_frame.pack_forget()
            self.manual_ip_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        else:
            self.manual_ip_frame.pack_forget()
            self.file_ip_frame.pack(fill=tk.BOTH, expand=True, pady=5)

    def browse_ip_file(self):
        """Browse for IP file"""
        filename = filedialog.askopenfilename(
            title="Select IP File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.ip_file_entry.delete(0, tk.END)
            self.ip_file_entry.insert(0, filename)

    def validate_ips(self):
        """Validate IP addresses"""
        self.ip_status.config(state=tk.NORMAL)
        self.ip_status.delete(1.0, tk.END)

        if self.ip_method.get() == "manual":
            lines = self.ip_text.get(1.0, tk.END).strip().split('\n')
            valid_ips, invalid_ips = IPValidator.validate_ip_list(lines)
        else:
            file_path = self.ip_file_entry.get()
            if not file_path:
                self.ip_status.insert(tk.END, "Please select an IP file\n")
                self.ip_status.config(state=tk.DISABLED)
                return

            valid_ips, invalid_ips = IPValidator.load_from_file(file_path)

        self.ip_list = valid_ips

        self.ip_status.insert(tk.END, f"Valid IPs: {len(valid_ips)}\n")
        if invalid_ips:
            self.ip_status.insert(tk.END, f"Invalid IPs: {len(invalid_ips)}\n\n")
            for invalid in invalid_ips:
                self.ip_status.insert(tk.END, f"  {invalid}\n")
        else:
            self.ip_status.insert(tk.END, "All IPs are valid!\n")

        self.ip_status.config(state=tk.DISABLED)

    def refresh_templates(self):
        """Refresh template list"""
        templates = self.template_manager.list_templates()
        template_names = [t['name'] for t in templates]
        self.template_combo['values'] = template_names

    def load_template_commands(self, event=None):
        """Load commands from selected template"""
        template_name = self.template_var.get()
        if not template_name:
            return

        # Find template ID
        templates = self.template_manager.list_templates()
        template_id = None
        for t in templates:
            if t['name'] == template_name:
                template_id = t['id']
                break

        if template_id:
            template_data = self.template_manager.load_template(template_id)
            if template_data and 'commands' in template_data:
                self.commands_text.delete(1.0, tk.END)
                self.commands_text.insert(1.0, '\n'.join(template_data['commands']))

    def load_commands_file(self):
        """Load commands from file"""
        filename = filedialog.askopenfilename(
            title="Select Commands File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    commands = f.read()
                self.commands_text.delete(1.0, tk.END)
                self.commands_text.insert(1.0, commands)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")

    def save_template(self):
        """Save current commands as template"""
        from tkinter import simpledialog

        name = simpledialog.askstring("Save Template", "Template name:")
        if not name:
            return

        description = simpledialog.askstring("Save Template", "Description (optional):")
        commands = self.commands_text.get(1.0, tk.END).strip().split('\n')

        template_id = name.lower().replace(' ', '_')
        if self.template_manager.save_template(template_id, name, description or "", commands):
            messagebox.showinfo("Success", "Template saved successfully!")
            self.refresh_templates()
        else:
            messagebox.showerror("Error", "Failed to save template")

    def start_execution(self):
        """Start execution process"""
        # Validate inputs
        if not self.ip_list:
            messagebox.showwarning("Warning", "Please validate IP addresses first")
            return

        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showwarning("Warning", "Please enter SSH credentials")
            return

        commands = self.commands_text.get(1.0, tk.END).strip().split('\n')
        commands = [cmd.strip() for cmd in commands if cmd.strip() and not cmd.strip().startswith('#')]

        if not commands:
            messagebox.showwarning("Warning", "Please enter commands to execute")
            return

        # Disable start button
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # Clear previous results
        self.execution_results = []
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        # Start execution in separate thread
        thread = threading.Thread(target=self.run_execution, args=(username, password, commands))
        thread.daemon = True
        thread.start()

    def run_execution(self, username, password, commands):
        """Run execution process"""
        try:
            # Step 1: Ping check (if enabled)
            if self.ping_check_var.get():
                self.log_message("Starting connectivity check...\n")
                checker = ConnectivityChecker()

                reachable_ips = []
                total = len(self.ip_list)
                completed = 0

                def ping_callback(ip, is_reachable, time_ms):
                    nonlocal completed
                    completed += 1
                    progress = (completed / total) * 50  # First 50% for ping
                    self.progress_queue.put(('progress', progress))

                    if is_reachable:
                        reachable_ips.append(ip)
                        self.log_message(f"  {ip}: Reachable ({time_ms:.2f}ms)\n")
                    else:
                        self.log_message(f"  {ip}: Unreachable\n")

                checker.ping_multiple(self.ip_list, callback=ping_callback, max_workers=10)

                if not reachable_ips:
                    self.log_message("\nNo devices are reachable. Aborting.\n")
                    self.progress_queue.put(('done', None))
                    return

                target_ips = reachable_ips
                self.log_message(f"\n{len(reachable_ips)}/{len(self.ip_list)} devices are reachable\n\n")
            else:
                target_ips = self.ip_list

            # Step 2: SSH execution
            self.log_message("Starting SSH execution...\n")

            credentials = SSHCredentials(
                username=username,
                password=password,
                enable_password=self.enable_password_entry.get(),
                port=int(self.port_entry.get())
            )

            ssh_handler = SSHHandler(credentials)

            total = len(target_ips)
            completed = 0

            def ssh_callback(result: SSHResult):
                nonlocal completed
                completed += 1
                progress = 50 + (completed / total) * 50  # Second 50% for SSH
                self.progress_queue.put(('progress', progress))

                self.execution_results.append(result)
                self.progress_queue.put(('result', result))

                if result.success:
                    self.log_message(f"  {result.ip}: SUCCESS ({result.execution_time:.2f}s)\n")
                else:
                    self.log_message(f"  {result.ip}: FAILED - {result.error}\n")

            max_workers = int(self.concurrent_spinbox.get())
            ssh_handler.execute_multiple(target_ips, commands, callback=ssh_callback, max_workers=max_workers)

            self.log_message("\nExecution completed!\n")

            # Add to history
            self.history_manager.add_entry(target_ips, commands)

        except Exception as e:
            self.log_message(f"\nError: {str(e)}\n")

        finally:
            self.progress_queue.put(('done', None))

    def stop_execution(self):
        """Stop execution (not fully implemented)"""
        messagebox.showinfo("Info", "Stop functionality not yet implemented")

    def log_message(self, message):
        """Add message to log"""
        self.progress_queue.put(('log', message))

    def clear_log(self):
        """Clear execution log"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

    def check_progress(self):
        """Check progress queue and update UI"""
        try:
            while True:
                item = self.progress_queue.get_nowait()
                item_type, data = item

                if item_type == 'progress':
                    self.progress_var.set(data)

                elif item_type == 'log':
                    self.log_text.config(state=tk.NORMAL)
                    self.log_text.insert(tk.END, data)
                    self.log_text.see(tk.END)
                    self.log_text.config(state=tk.DISABLED)

                elif item_type == 'result':
                    result = data
                    status = "SUCCESS" if result.success else "FAILED"
                    self.results_tree.insert("", tk.END, values=(
                        result.ip,
                        status,
                        f"{result.execution_time:.2f}s",
                        result.error or ""
                    ))

                    # Update summary
                    total = len(self.execution_results)
                    successful = sum(1 for r in self.execution_results if r.success)
                    failed = total - successful

                    self.total_label.config(text=f"Total Devices: {total}")
                    self.success_label.config(text=f"Successful: {successful}")
                    self.failed_label.config(text=f"Failed: {failed}")

                elif item_type == 'done':
                    self.start_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    self.progress_var.set(100)
                    self.status_label.config(text="Completed")

        except queue.Empty:
            pass

        # Schedule next check
        self.root.after(100, self.check_progress)

    def show_result_details(self, event):
        """Show detailed output for selected result"""
        selection = self.results_tree.selection()
        if not selection:
            return

        item = self.results_tree.item(selection[0])
        ip = item['values'][0]

        # Find result for this IP
        result = None
        for r in self.execution_results:
            if r.ip == ip:
                result = r
                break

        if not result:
            return

        # Show in new window
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"Results for {ip}")
        detail_window.geometry("800x600")

        output_text = scrolledtext.ScrolledText(detail_window)
        output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        output_text.insert(tk.END, f"IP: {result.ip}\n")
        output_text.insert(tk.END, f"Status: {'SUCCESS' if result.success else 'FAILED'}\n")
        output_text.insert(tk.END, f"Execution Time: {result.execution_time:.2f}s\n")
        output_text.insert(tk.END, f"Timestamp: {result.timestamp}\n")

        if result.error:
            output_text.insert(tk.END, f"\nError: {result.error}\n")

        output_text.insert(tk.END, "\n" + "="*80 + "\n")
        output_text.insert(tk.END, "Output:\n")
        output_text.insert(tk.END, "="*80 + "\n\n")
        output_text.insert(tk.END, result.output)

    def export_results(self, format_type):
        """Export results in specified format"""
        if not self.execution_results:
            messagebox.showwarning("Warning", "No results to export")
            return

        # Ask for file location
        filetypes = {
            'text': [("Text files", "*.txt")],
            'csv': [("CSV files", "*.csv")],
            'json': [("JSON files", "*.json")],
            'html': [("HTML files", "*.html")]
        }

        filename = filedialog.asksaveasfilename(
            title="Save Report",
            filetypes=filetypes.get(format_type, [("All files", "*.*")])
        )

        if not filename:
            return

        try:
            generator = ReportGenerator()

            if format_type == 'text':
                generator.generate_text_report(self.execution_results, filename)
            elif format_type == 'csv':
                generator.generate_csv_report(self.execution_results, filename)
            elif format_type == 'json':
                generator.generate_json_report(self.execution_results, filename)
            elif format_type == 'html':
                generator.generate_html_report(self.execution_results, filename)

            messagebox.showinfo("Success", f"Report exported successfully to {filename}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to export report: {e}")

    # Menu handlers
    def new_profile(self):
        """Create new profile"""
        # Clear all fields
        self.ip_text.delete(1.0, tk.END)
        self.commands_text.delete(1.0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.enable_password_entry.delete(0, tk.END)

    def save_profile(self):
        """Save current configuration as profile"""
        from tkinter import simpledialog

        name = simpledialog.askstring("Save Profile", "Profile name:")
        if not name:
            return

        description = simpledialog.askstring("Save Profile", "Description (optional):")

        # Get current configuration
        if self.ip_method.get() == "manual":
            ip_list = self.ip_text.get(1.0, tk.END).strip().split('\n')
        else:
            ip_list = [self.ip_file_entry.get()]

        commands = self.commands_text.get(1.0, tk.END).strip().split('\n')

        profile = Profile(
            name=name,
            description=description or "",
            ip_list=ip_list,
            commands=commands,
            username=self.username_entry.get(),
            port=int(self.port_entry.get()),
            concurrent_connections=int(self.concurrent_spinbox.get())
        )

        if self.config_manager.save_profile(profile, self.password_entry.get()):
            messagebox.showinfo("Success", "Profile saved successfully!")
        else:
            messagebox.showerror("Error", "Failed to save profile")

    def load_profile(self):
        """Load a saved profile"""
        profiles = self.config_manager.list_profiles()

        if not profiles:
            messagebox.showinfo("Info", "No saved profiles found")
            return

        # Show profile selection dialog
        from tkinter import simpledialog

        profile_window = tk.Toplevel(self.root)
        profile_window.title("Load Profile")
        profile_window.geometry("400x300")

        ttk.Label(profile_window, text="Select Profile:").pack(pady=10)

        listbox = tk.Listbox(profile_window)
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        for profile in profiles:
            listbox.insert(tk.END, profile)

        def load_selected():
            selection = listbox.curselection()
            if not selection:
                return

            profile_name = listbox.get(selection[0])
            result = self.config_manager.load_profile(profile_name)

            if result:
                profile, password = result

                # Load data into UI
                self.ip_text.delete(1.0, tk.END)
                self.ip_text.insert(1.0, '\n'.join(profile.ip_list))

                self.commands_text.delete(1.0, tk.END)
                self.commands_text.insert(1.0, '\n'.join(profile.commands))

                self.username_entry.delete(0, tk.END)
                self.username_entry.insert(0, profile.username)

                if password:
                    self.password_entry.delete(0, tk.END)
                    self.password_entry.insert(0, password)

                self.port_entry.delete(0, tk.END)
                self.port_entry.insert(0, str(profile.port))

                self.concurrent_spinbox.set(profile.concurrent_connections)

                profile_window.destroy()
                messagebox.showinfo("Success", "Profile loaded successfully!")

        ttk.Button(profile_window, text="Load", command=load_selected).pack(pady=10)

    def export_report(self):
        """Export last execution report"""
        self.export_results('html')

    def show_templates(self):
        """Show template manager dialog"""
        messagebox.showinfo("Templates", "Template manager - Feature coming soon!")

    def show_history(self):
        """Show execution history"""
        history = self.history_manager.get_recent(20)

        if not history:
            messagebox.showinfo("History", "No execution history found")
            return

        # Show history window
        history_window = tk.Toplevel(self.root)
        history_window.title("Execution History")
        history_window.geometry("800x400")

        # Create treeview
        columns = ("Timestamp", "Profile", "IPs", "Commands")
        tree = ttk.Treeview(history_window, columns=columns, show="headings")

        for col in columns:
            tree.heading(col, text=col)

        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Add history entries
        for entry in reversed(history):
            tree.insert("", tk.END, values=(
                entry.get('timestamp', ''),
                entry.get('profile', 'N/A'),
                entry.get('ip_count', 0),
                entry.get('command_count', 0)
            ))

    def show_settings(self):
        """Show settings dialog"""
        messagebox.showinfo("Settings", "Settings - Feature coming soon!")

    def show_about(self):
        """Show about dialog"""
        about_text = """
AutomationNet v2.0

Network Device Automation Tool

Features:
- Multi-device SSH automation
- IP validation and connectivity checking
- Configuration profiles
- Command templates
- Execution history
- Report generation (Text, CSV, JSON, HTML)

Developed with Python & Tkinter
        """
        messagebox.showinfo("About AutomationNet", about_text)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = AutomationNetGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
