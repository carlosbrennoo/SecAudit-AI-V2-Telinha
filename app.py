import customtkinter as ctk
import threading
import os
from tkinter import filedialog
from datetime import datetime

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

BG         = "#0D1117"
SURFACE    = "#161B22"
SURFACE2   = "#21262D"
BORDER     = "#30363D"
CYAN       = "#00D4FF"
CYAN_DIM   = "#00A3C4"
GREEN      = "#3FB950"
YELLOW     = "#D29922"
ORANGE     = "#F0883E"
BLUE       = "#58A6FF"
RED        = "#F85149"
TEXT       = "#E6EDF3"
TEXT_MUTED = "#8B949E"
FONT_MONO  = ("Consolas", 11)
FONT_TITLE = ("Segoe UI", 24, "bold")
FONT_LABEL = ("Segoe UI", 12)
FONT_SMALL = ("Segoe UI", 10)

# Cor por severidade (usado para colorir relatório e cards)
SEV_CORES = {
    "critico": RED,
    "perigo":  ORANGE,
    "alerta":  YELLOW,
    "medio":   BLUE,
    "baixo":   TEXT_MUTED,
    "ok":      GREEN,
    "erro":    RED,
}

# Lista de módulos vem do audit.py para ficar sempre sincronizada
try:
    from audit import MODULOS
except ImportError:
    MODULOS = ["S3", "IAM", "Chaves", "Security Groups", "CloudTrail", "EC2"]


# Tela 1 - Login (só credenciais AWS)

class TelaLogin(ctk.CTkFrame):
    def __init__(self, master, on_entrar):
        super().__init__(master, fg_color=BG, corner_radius=0)
        self._on_entrar = on_entrar
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build()

    def _build(self):
        # Card central
        card = ctk.CTkFrame(self, fg_color=SURFACE, corner_radius=14,
                            border_width=1, border_color=BORDER, width=440)
        card.grid(row=0, column=0)
        card.grid_columnconfigure(0, weight=1)

        # Ícone
        ctk.CTkLabel(card, text="⬡", font=("Segoe UI", 48),
                     text_color=CYAN).grid(row=0, column=0, pady=(36, 0))

        # Título
        ctk.CTkLabel(card, text="SecAudit AI",
                     font=FONT_TITLE, text_color=TEXT).grid(row=1, column=0, pady=(6, 2))

        ctk.CTkLabel(card,
                     text="Auditoria de segurança AWS com IA local",
                     font=FONT_SMALL, text_color=TEXT_MUTED).grid(row=2, column=0, pady=(0, 28))

        # Separador
        ctk.CTkFrame(card, height=1, fg_color=BORDER).grid(
            row=3, column=0, sticky="ew", padx=32, pady=(0, 24))

        # Label de credenciais
        ctk.CTkLabel(card, text="CREDENCIAIS AWS",
                     font=("Segoe UI", 10, "bold"),
                     text_color=CYAN).grid(row=4, column=0, sticky="w", padx=36, pady=(0, 6))

        # Access Key ID da AWS
        ctk.CTkLabel(card, text="Access Key ID",
                     font=FONT_SMALL, text_color=TEXT_MUTED).grid(
            row=5, column=0, sticky="w", padx=36)

        self.entry_key = ctk.CTkEntry(
            card, placeholder_text="AKIA...",
            fg_color=SURFACE2, border_color=BORDER,
            text_color=TEXT, font=FONT_MONO,
            height=40, width=368, corner_radius=8
        )
        self.entry_key.grid(row=6, column=0, padx=36, pady=(4, 14))

        # Secret Access Key da AWS
        ctk.CTkLabel(card, text="Secret Access Key",
                     font=FONT_SMALL, text_color=TEXT_MUTED).grid(
            row=7, column=0, sticky="w", padx=36)

        self.entry_secret = ctk.CTkEntry(
            card, placeholder_text="••••••••••••••••",
            show="•", fg_color=SURFACE2, border_color=BORDER,
            text_color=TEXT, font=FONT_MONO,
            height=40, width=368, corner_radius=8
        )
        self.entry_secret.grid(row=8, column=0, padx=36, pady=(4, 4))

        # Mostrar / ocultar a secret key
        self.mostrar_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            card, text="Mostrar Secret Key", variable=self.mostrar_var,
            command=self._toggle_secret, font=("Segoe UI", 9),
            text_color=TEXT_MUTED, fg_color=CYAN_DIM, hover_color=CYAN,
            checkbox_width=16, checkbox_height=16, corner_radius=4
        ).grid(row=9, column=0, sticky="w", padx=36, pady=(0, 2))

        # Aviso segurança
        ctk.CTkLabel(
            card,
            text="🔒  As chaves são usadas apenas durante a análise e apagadas em seguida.",
            font=("Segoe UI", 9), text_color=TEXT_MUTED, wraplength=340
        ).grid(row=10, column=0, padx=36, pady=(6, 18))

        # Erro
        self.lbl_erro = ctk.CTkLabel(card, text="",
                                     font=FONT_SMALL, text_color=RED)
        self.lbl_erro.grid(row=11, column=0)

        # Botão pra iniciar a auditoria
        self.btn = ctk.CTkButton(
            card, text="Iniciar Auditoria  →",
            font=("Segoe UI", 13, "bold"),
            fg_color=CYAN_DIM, hover_color=CYAN,
            text_color="#0D1117",
            height=44, width=368, corner_radius=8,
            command=self._entrar
        )
        self.btn.grid(row=12, column=0, padx=36, pady=(8, 36))

        # Bind Enter
        self.entry_secret.bind("<Return>", lambda e: self._entrar())
        self.entry_key.bind("<Return>", lambda e: self.entry_secret.focus())

    def _toggle_secret(self):
        self.entry_secret.configure(show="" if self.mostrar_var.get() else "•")

    def _entrar(self):
        key    = self.entry_key.get().strip()
        secret = self.entry_secret.get().strip()

        if not key or not secret:
            self.lbl_erro.configure(text="⚠  Coloque as duas chaves para continuar.")
            return

        self.lbl_erro.configure(text="")
        self.btn.configure(state="disabled", text="Carregando...")
        self._on_entrar(key, secret)



# Tela 2 - Auditoria

class TelaAuditoria(ctk.CTkFrame):
    def __init__(self, master, aws_key, aws_secret, on_voltar):
        super().__init__(master, fg_color=BG, corner_radius=0)
        self._aws_key    = aws_key
        self._aws_secret = aws_secret
        self._on_voltar  = on_voltar
        self._relatorio  = ""
        self._achados    = ""

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build()
        self._iniciar_auditoria()

    def _build(self):
        main = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        main.grid(row=0, column=0, sticky="nsew", padx=32, pady=24)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)

        # -- Header --
        header = ctk.CTkFrame(main, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(header, text="⬡", font=("Segoe UI", 28),
                     text_color=CYAN).grid(row=0, column=0, padx=(0, 10), rowspan=2)

        ctk.CTkLabel(header, text="SecAudit AI",
                     font=("Segoe UI", 20, "bold"),
                     text_color=TEXT, anchor="w").grid(row=0, column=1, sticky="w")

        self.lbl_status = ctk.CTkLabel(
            header, text="Iniciando análise...",
            font=FONT_SMALL, text_color=CYAN, anchor="w"
        )
        self.lbl_status.grid(row=1, column=1, sticky="w")

        ctk.CTkFrame(main, height=1, fg_color=BORDER).grid(
            row=0, column=0, sticky="ew", pady=(68, 0))

        # -- Opções + barra de progresso --
        opts = ctk.CTkFrame(main, fg_color="transparent")
        opts.grid(row=1, column=0, sticky="ew", pady=(10, 8))
        opts.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(opts, text="Tipo de relatório:",
                     font=FONT_LABEL, text_color=TEXT).grid(row=0, column=0, padx=(0, 12))

        self.modo_var = ctk.StringVar(value="Detalhado")
        seg = ctk.CTkSegmentedButton(
            opts,
            values=["Detalhado", "Resumido"],
            variable=self.modo_var,
            fg_color=SURFACE2,
            selected_color=CYAN_DIM,
            selected_hover_color=CYAN,
            unselected_color=SURFACE2,
            unselected_hover_color=BORDER,
            text_color=TEXT,
            font=FONT_LABEL,
        )
        seg.grid(row=0, column=1, sticky="w")

        self.progressbar = ctk.CTkProgressBar(
            opts, fg_color=SURFACE2, progress_color=CYAN,
            height=6, corner_radius=3, width=200
        )
        self.progressbar.set(0)
        self.progressbar.grid(row=0, column=2, padx=(16, 0))

        # -- Tabs --
        tab_view = ctk.CTkTabview(
            main,
            fg_color=SURFACE,
            segmented_button_fg_color=SURFACE2,
            segmented_button_selected_color=CYAN_DIM,
            segmented_button_selected_hover_color=CYAN,
            segmented_button_unselected_color=SURFACE2,
            segmented_button_unselected_hover_color=BORDER,
            text_color=TEXT,
            border_width=1,
            border_color=BORDER,
            corner_radius=10,
        )
        tab_view.grid(row=2, column=0, sticky="nsew")
        tab_view.grid_columnconfigure(0, weight=1)
        tab_view.grid_rowconfigure(0, weight=1)

        tab_view.add("Progresso")
        tab_view.add("Achados")
        tab_view.add("Relatório")
        self._tab_view = tab_view

        self._build_tab_progresso(tab_view.tab("Progresso"))
        self.txt_achados = self._build_textbox(tab_view.tab("Achados"),
                                               "Os achados aparecerão aqui assim que a varredura terminar...")
        self.txt = self._build_textbox(tab_view.tab("Relatório"),
                                       "O relatório com IA aparecerá aqui após a auditoria concluir...")

        # -- Footer --
        footer = ctk.CTkFrame(main, fg_color="transparent")
        footer.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        footer.grid_columnconfigure(2, weight=1)

        self.lbl_risco = ctk.CTkLabel(
            footer, text="", font=("Segoe UI", 12, "bold"), anchor="w")
        self.lbl_risco.grid(row=0, column=0, sticky="w", padx=(0, 14))

        self.lbl_contagem = ctk.CTkLabel(
            footer, text="", font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w")
        self.lbl_contagem.grid(row=0, column=1, sticky="w")

        self.btn_nova = ctk.CTkButton(
            footer, text="Nova auditoria", font=FONT_SMALL,
            fg_color=SURFACE2, hover_color=BORDER, text_color=TEXT,
            height=30, width=110, corner_radius=6,
            command=self._nova, state="disabled"
        )
        self.btn_nova.grid(row=0, column=3, padx=(0, 8))

        self.btn_copiar = ctk.CTkButton(
            footer, text="Copiar", font=FONT_SMALL,
            fg_color=SURFACE2, hover_color=BORDER, text_color=TEXT,
            height=30, width=80, corner_radius=6,
            command=self._copiar, state="disabled"
        )
        self.btn_copiar.grid(row=0, column=4, padx=(0, 8))

        self.btn_salvar = ctk.CTkButton(
            footer, text="Salvar Relatório", font=FONT_SMALL,
            fg_color=SURFACE2, hover_color=BORDER, text_color=TEXT,
            height=30, corner_radius=6,
            command=self._salvar, state="disabled"
        )
        self.btn_salvar.grid(row=0, column=5)

    def _build_tab_progresso(self, tab):
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)

        # Scrollável pois agora são muitos módulos
        grid = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        grid.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        grid.grid_columnconfigure((0, 1, 2), weight=1)

        self._modulo_widgets = {}
        for i, nome in enumerate(MODULOS):
            w = self._modulo_card(grid, nome)
            w.grid(row=i // 3, column=i % 3, padx=6, pady=6, sticky="ew")
            self._modulo_widgets[nome] = w

    def _modulo_card(self, parent, nome):
        frame = ctk.CTkFrame(parent, fg_color=SURFACE2, corner_radius=8,
                             border_width=1, border_color=BORDER)
        frame.grid_columnconfigure(1, weight=1)

        dot = ctk.CTkLabel(frame, text="●", font=("Segoe UI", 14),
                           text_color=BORDER, width=24)
        dot.grid(row=0, column=0, padx=(10, 4), pady=14)

        lbl = ctk.CTkLabel(frame, text=nome, font=FONT_LABEL,
                           text_color=TEXT_MUTED, anchor="w")
        lbl.grid(row=0, column=1, sticky="w", padx=(0, 10))

        frame._dot = dot
        frame._lbl = lbl
        return frame

    def _build_textbox(self, tab, placeholder):
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)

        box = ctk.CTkTextbox(
            tab, fg_color=SURFACE2, text_color=TEXT,
            font=("Consolas", 13), wrap="word", corner_radius=6,
            border_width=0,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=TEXT_MUTED,
        )
        box.grid(row=0, column=0, sticky="nsew")
        for sev, cor in SEV_CORES.items():
            box.tag_config(sev, foreground=cor)
        box.insert("end", placeholder + "\n")
        box.configure(state="disabled")
        return box

    @staticmethod
    def _tag_da_linha(linha):
        for tag in ("critico", "perigo", "alerta", "medio", "baixo", "ok"):
            if f"[{tag.upper()}]" in linha:
                return tag
        if "[ERRO]" in linha:
            return "erro"
        return None

    def _preencher(self, box, texto):
        box.configure(state="normal")
        box.delete("1.0", "end")
        for linha in texto.split("\n"):
            tag = self._tag_da_linha(linha)
            box.insert("end", linha + "\n", tag if tag else ())
        box.configure(state="disabled")


    # -- Lógica da auditoria --

    def _iniciar_auditoria(self):
        threading.Thread(target=self._tarefa, daemon=True).start()

    def _tarefa(self):
        try:
            try:
                from audit import rodar_auditoria, gerar_relatorio_ia
            except ImportError:
                self.after(0, lambda: self._falhar("audit.py não encontrado."))
                return

            concluidos = [0]

            def callback(nome, status, extra=None):
                if status == "iniciando":
                    self.after(0, lambda n=nome: self._modulo_status(n, "iniciando"))
                elif status == "concluido":
                    concluidos[0] += 1
                    prog = concluidos[0] / len(MODULOS)
                    self.after(0, lambda p=prog: self.progressbar.set(p))
                    self.after(0, lambda c=concluidos[0]: self._set_status(
                        f"Analisando... {c}/{len(MODULOS)} módulos concluídos", TEXT_MUTED))
                elif status == "resultado":
                    self.after(0, lambda n=nome, s=extra: self._modulo_status(n, "resultado", s))

            secoes, dados_finais, contagens = rodar_auditoria(
                self._aws_key, self._aws_secret, callback)

            # Mostra os achados estruturados imediatamente (não depende de IA)
            self._achados = self._montar_achados(secoes, contagens)
            self.after(0, lambda: self._exibir_achados(contagens))

            # Camada extra: relatório com IA local
            self.after(0, lambda: self._set_status("Gerando relatório com IA local...", CYAN))
            modo      = self.modo_var.get().lower()
            relatorio = gerar_relatorio_ia("", dados_finais, modo)
            self._relatorio = relatorio

            # Apaga credenciais da memória
            self._aws_key = ""
            self._aws_secret = ""

            self.after(0, lambda: self._exibir_relatorio(relatorio))

        except Exception as e:
            self._aws_key = ""
            self._aws_secret = ""
            self.after(0, lambda err=e: self._falhar(str(err)))

    def _montar_achados(self, secoes, contagens):
        linhas = []
        for secao, itens in secoes.items():
            linhas.append(f"=== {secao} ===")
            for item in itens:
                linhas.append(f"  {item}")
            linhas.append("")
        return "\n".join(linhas)

    def _exibir_achados(self, contagens):
        self._preencher(self.txt_achados, self._achados)
        self._tab_view.set("Achados")

        c = contagens
        score = c.get("score", 0)
        rotulo, cor = self._risco(score)
        self.lbl_risco.configure(text=f"⚠ {rotulo} (score {score})", text_color=cor)
        self.lbl_contagem.configure(
            text=(f"🔴 {c['criticos']}   🟠 {c['perigos']}   "
                  f"🟡 {c['alertas']}   🔵 {c['medios']}   ⚪ {c.get('baixos', 0)}"),
            text_color=TEXT
        )
        self.progressbar.set(1)
        self.btn_salvar.configure(state="normal")
        self.btn_copiar.configure(state="normal")

    def _exibir_relatorio(self, relatorio):
        self._preencher(self.txt, relatorio)
        if relatorio.startswith("Erro ao conectar com Ollama"):
            self._set_status("⚠  Achados prontos. IA indisponível (Ollama offline).", YELLOW)
        else:
            self._tab_view.set("Relatório")
            self._set_status("✔  Auditoria concluída.", GREEN)
        self.btn_nova.configure(state="normal")

    def _falhar(self, msg):
        self._set_status(f"❌  {msg}", RED)
        self._preencher(self.txt_achados, f"[ERRO] A auditoria falhou:\n\n{msg}")
        self._tab_view.set("Achados")
        self.btn_nova.configure(state="normal")
        self.progressbar.configure(progress_color=RED)
        self.progressbar.set(1)

    @staticmethod
    def _risco(score):
        if score == 0:
            return "Seguro", GREEN
        if score <= 30:
            return "Risco Baixo", BLUE
        if score <= 80:
            return "Risco Médio", ORANGE
        return "Risco Alto", RED

    def _nova(self):
        if self._on_voltar:
            self._on_voltar()

    def _copiar(self):
        conteudo = self._relatorio or self._achados
        if not conteudo:
            return
        self.clipboard_clear()
        self.clipboard_append(conteudo)
        self._set_status("✔  Copiado para a área de transferência.", GREEN)

    def _salvar(self):
        if not self._achados and not self._relatorio:
            return
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        path  = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Texto", "*.txt"), ("HTML", "*.html"), ("Todos", "*.*")],
            initialfile=f"relatorio_{ts}.txt",
            title="Salvar relatório"
        )
        if not path:
            return

        rel = self._relatorio if self._relatorio and not self._relatorio.startswith("Erro ao conectar") else ""
        texto = (
            (rel + "\n\n" if rel else "")
            + "────────────── ACHADOS DETALHADOS ──────────────\n\n"
            + self._achados
        )

        if path.lower().endswith(".html"):
            conteudo = self._relatorio_html(texto, ts)
        else:
            conteudo = texto
        with open(path, "w", encoding="utf-8") as f:
            f.write(conteudo)
        self._set_status(f"✔  Salvo em {os.path.basename(path)}", GREEN)

    @staticmethod
    def _relatorio_html(texto, ts):
        import html
        corpo = html.escape(texto)
        return (
            "<!DOCTYPE html><html lang='pt-br'><head><meta charset='utf-8'>"
            "<title>SecAudit AI — Relatório</title>"
            "<style>"
            "body{background:#0D1117;color:#E6EDF3;font-family:Segoe UI,Arial,sans-serif;margin:0;padding:40px;}"
            "h1{color:#00D4FF;} .meta{color:#8B949E;margin-bottom:24px;}"
            "pre{background:#161B22;border:1px solid #30363D;border-radius:10px;"
            "padding:24px;white-space:pre-wrap;font-family:Consolas,monospace;line-height:1.5;}"
            "</style></head><body>"
            "<h1>⬡ SecAudit AI — Relatório de Auditoria AWS</h1>"
            f"<div class='meta'>Gerado em {ts}</div>"
            f"<pre>{corpo}</pre></body></html>"
        )

    def _set_status(self, msg, cor=TEXT_MUTED):
        self.lbl_status.configure(text=msg, text_color=cor)

    def _modulo_status(self, nome, status, extra=None):
        w = self._modulo_widgets.get(nome)
        if not w:
            return
        if status == "iniciando":
            w._dot.configure(text_color=YELLOW)
            w._lbl.configure(text_color=TEXT)
            w.configure(border_color=YELLOW)
        elif status == "resultado":
            cor = SEV_CORES.get(extra, GREEN)
            w._dot.configure(text_color=cor)
            w._lbl.configure(text_color=cor)
            w.configure(border_color=cor)


# ─────────────────────────────────────────────────────────────────────────────
# App — gerencia a troca de telas
# ─────────────────────────────────────────────────────────────────────────────

class SecAuditApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SecAudit AI")
        self.geometry("520x600")
        self.minsize(480, 560)
        self.configure(fg_color=BG)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._tela_atual = None
        self._mostrar_login()

    def _mostrar_login(self):
        if self._tela_atual:
            self._tela_atual.destroy()
        self.geometry("520x600")
        self.resizable(False, False)
        tela = TelaLogin(self, on_entrar=self._ir_para_auditoria)
        tela.grid(row=0, column=0, sticky="nsew")
        self._tela_atual = tela

    def _ir_para_auditoria(self, aws_key, aws_secret):
        self._tela_atual.destroy()
        self.geometry("960x720")
        self.minsize(860, 640)
        self.resizable(True, True)
        tela = TelaAuditoria(self, aws_key, aws_secret, on_voltar=self._mostrar_login)
        tela.grid(row=0, column=0, sticky="nsew")
        self._tela_atual = tela


if __name__ == "__main__":
    app = SecAuditApp()
    app.mainloop()
