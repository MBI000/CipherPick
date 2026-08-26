"""
CipherPick PyQt5 — Background Task Manager
Uses QTimer for non-blocking log-file polling.
"""
import os
import subprocess
import sys
from PyQt5.QtCore import QObject, QTimer, pyqtSignal

class TaskManager(QObject):
    task_done = pyqtSignal(str, int)
    line_received = pyqtSignal(str, str)

    def __init__(self, output_pane=None):
        super().__init__()
        self._output_pane = output_pane
        self._tasks = {}
        self._timers = {}

    def set_output_pane(self, pane):
        self._output_pane = pane

    def start(self, task_id, cmd, cwd=None, env=None):
        if self.is_running(task_id):
            return False

        os.makedirs('.cipherpick_logs', exist_ok=True)
        log_path = f'.cipherpick_logs/{task_id}.log'
        log_file = open(log_path, 'w', buffering=1, encoding='utf-8')

        proc_env = os.environ.copy()
        if env:
            proc_env.update(env)
        proc_env['PYTHONUNBUFFERED'] = '1'

        process = subprocess.Popen(
            cmd,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            env=proc_env,
            cwd=cwd,
        )

        self._tasks[task_id] = {
            'process': process,
            'log_path': log_path,
            'log_file': log_file,
            'line_count': 0,
        }

        timer = QTimer(self)
        timer.timeout.connect(lambda: self._poll(task_id))
        timer.start(150)
        self._timers[task_id] = timer
        return True

    def stop(self, task_id):
        task = self._tasks.get(task_id)
        if not task:
            return
        
        timer = self._timers.get(task_id)
        if timer:
            timer.stop()
            del self._timers[task_id]

        proc = task['process']
        if proc.poll() is None:
            proc.terminate()
        
        if not task['log_file'].closed:
            task['log_file'].close()
        
        del self._tasks[task_id]

    def stop_all(self):
        for task_id in list(self._tasks.keys()):
            self.stop(task_id)

    def is_running(self, task_id):
        task = self._tasks.get(task_id)
        return task and task['process'].poll() is None

    def _poll(self, task_id):
        task = self._tasks.get(task_id)
        if not task:
            return

        new_lines = self._read_new_lines(task)
        if new_lines:
            for line in new_lines:
                self.line_received.emit(task_id, line + '\n')
                if self._output_pane:
                    self._output_pane.append_ansi(line + '\n')

        if task['process'].poll() is not None:
            # Finished
            final_lines = self._read_new_lines(task)
            if final_lines:
                for line in final_lines:
                    self.line_received.emit(task_id, line + '\n')
                    if self._output_pane:
                        self._output_pane.append_ansi(line + '\n')

            rc = task['process'].returncode
            if self._output_pane:
                color = '#00ff00' if rc == 0 else '#ff003c'
                self._output_pane.append_ansi(f"\n<span style='color: {color};'>[+] Task '{task_id}' finished (exit code {rc}).</span>\n")

            self.task_done.emit(task_id, rc)
            self.stop(task_id)

    def _read_new_lines(self, task):
        try:
            with open(task['log_path'], 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = f.read().splitlines()
            new = all_lines[task['line_count']:]
            task['line_count'] = len(all_lines)
            return new
        except Exception:
            return []
