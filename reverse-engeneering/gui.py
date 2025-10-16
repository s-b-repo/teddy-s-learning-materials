# gui.py
# Tkinter GUI for the quiz with a scrollable page area.

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import math
from questions import QUESTIONS

QUESTIONS_PER_PAGE = 6

class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        self.canvas = tk.Canvas(self, borderwidth=0, highlightthickness=0)
        self.vscroll = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vscroll.set)
        self.inner = ttk.Frame(self.canvas)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.vscroll.pack(side="right", fill="y")
        self.window = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")

        self.inner.bind("<Configure>", self._on_frame_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        # Mouse wheel bindings
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)   # Windows, macOS
        self.canvas.bind_all("<Button-4>", self._on_mousewheel)     # Linux up
        self.canvas.bind_all("<Button-5>", self._on_mousewheel)     # Linux down

    def _on_frame_configure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self.canvas.itemconfig(self.window, width=event.width)

    def _on_mousewheel(self, event):
        if hasattr(event, "num"):
            if event.num == 4:
                delta = -1
            elif event.num == 5:
                delta = 1
            else:
                delta = 0
        else:
            delta = -1 * int(event.delta / 120) if event.delta else 0
        self.canvas.yview_scroll(delta, "units")

class QuizApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("C++ Reverse-Engineering Quiz")
        self.geometry("900x700")
        self.questions = QUESTIONS[:]  # copy
        self.total_pages = max(1, math.ceil(len(self.questions) / QUESTIONS_PER_PAGE))
        self.current_page = 0
        self.user_answers = {}
        self.result_labels = {}
        self._build_ui()
        self.show_page(0)

    def _build_ui(self):
        header = ttk.Label(self, text="C++ Reverse-Engineering Fundamentals", font=("Segoe UI", 16))
        header.pack(pady=8)

        self.scroll_frame = ScrollableFrame(self)
        self.scroll_frame.pack(fill="both", expand=True, padx=8, pady=4)

        nav_frame = ttk.Frame(self)
        nav_frame.pack(fill="x", pady=6)

        self.prev_btn = ttk.Button(nav_frame, text="Previous Page", command=self.prev_page)
        self.prev_btn.pack(side="left", padx=6)

        self.page_label = ttk.Label(nav_frame, text="")
        self.page_label.pack(side="left", padx=10)

        self.next_btn = ttk.Button(nav_frame, text="Next Page", command=self.next_page)
        self.next_btn.pack(side="left", padx=6)

        help_btn = ttk.Button(nav_frame, text="How to add questions", command=self.show_add_instructions)
        help_btn.pack(side="right", padx=6)

    def clear_container(self):
        for w in self.scroll_frame.inner.winfo_children():
            w.destroy()
        self.result_labels.clear()

    def show_page(self, page_index: int):
        self.clear_container()
        self.current_page = max(0, min(page_index, self.total_pages - 1))
        start = self.current_page * QUESTIONS_PER_PAGE
        end = start + QUESTIONS_PER_PAGE
        page_items = self.questions[start:end]
        self.page_label.config(text=f"Page {self.current_page + 1} of {self.total_pages}")

        for q in page_items:
            qframe = ttk.LabelFrame(self.scroll_frame.inner, text=f"Q {q['id']}")
            qframe.pack(fill="x", padx=10, pady=6, ipady=6)

            prompt = scrolledtext.ScrolledText(qframe, height=4, wrap="word")
            prompt.insert("1.0", q["prompt"])
            prompt.configure(state="disabled")
            prompt.pack(fill="x", padx=6, pady=4)

            if q["type"] == "mcq":
                var = tk.IntVar(value=-1)
                prev = self.user_answers.get(q["id"])
                if isinstance(prev, int):
                    var.set(prev)
                for idx, choice in enumerate(q["choices"]):
                    rb = ttk.Radiobutton(qframe, text=choice, variable=var, value=idx)
                    rb.pack(anchor="w", padx=8)
                var.trace_add("write", lambda *args, qid=q["id"], v=var: self._on_mcq_change(qid, v))
                submit = ttk.Button(qframe, text="Submit", command=lambda q=q, v=var: self.check_answer(q, v.get()))
                submit.pack(side="right", padx=6, pady=6)

            else:  # text
                entry = ttk.Entry(qframe, width=80)
                prev = self.user_answers.get(q["id"])
                if isinstance(prev, str):
                    entry.insert(0, prev)
                entry.pack(fill="x", padx=6, pady=4)
                entry.bind("<Return>", lambda ev, q=q, e=entry: self.check_answer(q, e.get()))
                submit = ttk.Button(qframe, text="Submit", command=lambda q=q, e=entry: self.check_answer(q, e.get()))
                submit.pack(side="right", padx=6, pady=6)

            hint = q.get("hint")
            if hint:
                hint_btn = ttk.Button(qframe, text="Hint", command=lambda h=hint: messagebox.showinfo("Hint", h))
                hint_btn.pack(side="right", padx=6)

            res_lbl = ttk.Label(qframe, text="", foreground="blue")
            res_lbl.pack(anchor="w", padx=6, pady=4)
            self.result_labels[q["id"]] = res_lbl

        self.prev_btn.config(state="normal" if self.current_page > 0 else "disabled")
        self.next_btn.config(state="normal" if self.current_page < self.total_pages - 1 else "disabled")
        self.scroll_frame.canvas.yview_moveto(0)

    def _on_mcq_change(self, qid, var):
        try:
            self.user_answers[qid] = var.get()
        except Exception:
            pass

    def check_answer(self, question, user_input):
        qid = question["id"]
        correct = False
        if question["type"] == "mcq":
            if not isinstance(user_input, int) or user_input < 0:
                self.result_labels[qid].config(text="Please select an option.", foreground="orange")
                return
            correct = (user_input == question["answer"])
        else:
            checker = question["answer"]
            if callable(checker):
                try:
                    correct = bool(checker(str(user_input)))
                except Exception:
                    correct = False
            else:
                correct = str(user_input).strip().lower() == str(checker).strip().lower()
            self.user_answers[qid] = str(user_input)

        if correct:
            self.result_labels[qid].config(text="Correct", foreground="green")
        else:
            self.result_labels[qid].config(text="Incorrect", foreground="red")

    def prev_page(self):
        self.show_page(self.current_page - 1)

    def next_page(self):
        self.show_page(self.current_page + 1)

    def show_add_instructions(self):
        text = (
            "To add or edit questions, open questions.py and modify the QUESTIONS list.\n\n"
            "Each entry is a dict with: id, type ('mcq' or 'text'), prompt, choices (for mcq), "
            "answer (index for mcq or string/function for text), and optional hint.\n\n"
            "After adding questions, restart this GUI to load the new ones."
        )
        messagebox.showinfo("Adding Questions", text)

if __name__ == "__main__":
    app = QuizApp()
    app.mainloop()
