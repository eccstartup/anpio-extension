import {
  buildAwikiIdentity,
  generateMnemonicPhrase,
  isValidMnemonic,
  multibaseEd25519,
  parseEd25519PrivateKey,
} from '../lib/anp'
import type {
  ActiveKeyRef,
  BgRequest,
  PendingRequest,
  ServerConfig,
  StoredAccount,
  StoredKey,
  Wallet,
} from '../protocol'

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

type View = 'secret' | 'unlock' | 'register' | 'home' | 'wallet' | 'sign' | 'servers'
type SecretSource = 'generate' | 'mnemonic' | 'key'
type SecretStep = 'source' | 'recall' | 'meta'

const VIEWS: View[] = ['secret', 'unlock', 'register', 'home', 'wallet', 'sign', 'servers']

interface State {
  status: string
  unlocked: boolean
  account: StoredAccount | null
  activeRef: ActiveKeyRef | null
  pending: PendingRequest[]
  servers: ServerConfig[]
  defaultServerId: string
}

interface RegDraft {
  walletId: string
  handle: string
  email: string
  invite: string
  verified: boolean | null
  note: string
}

let lastState: State | null = null
let currentView: View | null = null
let renderSeq = 0

let manualView: 'secret' | 'servers' | null = null
let detailWalletId: string | null = null
let regWalletId: string | null = null

let secretMode: 'create' | 'add' = 'create'
let secretSource: SecretSource = 'generate'
let secretStep: SecretStep = 'source'
let generatedMnemonic = ''
let importedKey: ReturnType<typeof parseEd25519PrivateKey> | null = null

let regDraft: RegDraft | null = null
let emailPollTimer: number | null = null
let emailPollUntil = 0
let emailPollWalletId: string | null = null

function $<T extends HTMLElement = HTMLElement>(id: string): T {
  const el = document.getElementById(id)
  if (!el) throw new Error(`missing #${id}`)
  return el as T
}

function input(id: string): HTMLInputElement {
  return $(id) as HTMLInputElement
}

function textarea(id: string): HTMLTextAreaElement {
  return $(id) as HTMLTextAreaElement
}

function select(id: string): HTMLSelectElement {
  return $(id) as HTMLSelectElement
}

function hide(el: HTMLElement, hidden: boolean): void {
  el.classList.toggle('hidden', hidden)
}

function clear(el: HTMLElement): void {
  el.textContent = ''
}

function tag(text: string, cls = ''): HTMLElement {
  const el = document.createElement('span')
  el.className = `tag ${cls}`.trim()
  el.textContent = text
  return el
}

function short(value: string, max = 54): string {
  if (value.length <= max) return value
  return `${value.slice(0, max - 1)}…`
}

type ApiResponse = { status: string; [key: string]: unknown }

function send<T = ApiResponse>(msg: BgRequest): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(msg, (resp: T) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message))
        return
      }
      if (resp === undefined) {
        reject(new Error('钱包后台没有响应'))
        return
      }
      resolve(resp)
    })
  })
}

function walletById(account: StoredAccount | null, id: string | null): Wallet | null {
  if (!account || !id) return null
  return account.wallets.find((w) => w.id === id) ?? null
}

function effectiveMode(wallet: Wallet): 'did_document' | 'aggregate' {
  return wallet.registerMode === 'aggregate' ? 'aggregate' : 'did_document'
}

function serverById(state: State, id: string | null): ServerConfig | null {
  if (!id) return null
  return state.servers.find((s) => s.id === id) ?? null
}

function serverForWallet(state: State, wallet: Wallet): ServerConfig | null {
  return serverById(state, wallet.serverId)
}

function walletServerLabel(state: State, wallet: Wallet): string {
  if (effectiveMode(wallet) === 'aggregate') return '旧聚合 localhost'
  const server = serverForWallet(state, wallet)
  if (!server) return '服务器已移除'
  return `${server.label} · ${server.didDomain}`
}

function activeWallet(state: State): Wallet | null {
  const account = state.account
  if (!account) return null
  const id = state.activeRef?.walletId ?? account.activeWalletId
  return walletById(account, id)
}

function isLockedResponse(resp: { status?: string }): boolean {
  return resp.status === 'locked'
}

async function render(): Promise<void> {
  const seq = ++renderSeq
  let state: State
  try {
    state = await send<State>({ type: 'anp-wallet/get-state' })
  } catch (e) {
    $('lock-pill').textContent = '后台错误'
    return
  }
  if (seq !== renderSeq) return
  lastState = state
  if (!state || state.status !== 'ok') {
    $('lock-pill').textContent = '状态错误'
    return
  }

  const account = state.account
  const unlocked = Boolean(state.unlocked)
  if (!account || account.wallets.length === 0) {
    secretMode = 'create'
  }

  const lockPill = $('lock-pill')
  lockPill.textContent = !account ? '未初始化' : unlocked ? '已解锁' : '已锁定'
  lockPill.classList.toggle('ok', unlocked)
  lockPill.classList.toggle('warn', Boolean(account) && !unlocked)
  document.querySelector('header')?.classList.toggle('unlocked', unlocked)

  let view: View
  if (!account || account.wallets.length === 0) {
    view = 'secret'
  } else if (!unlocked) {
    view = 'unlock'
  } else if (state.pending.length > 0) {
    view = 'sign'
  } else if (regWalletId) {
    view = 'register'
  } else if (detailWalletId) {
    view = 'wallet'
  } else if (manualView === 'secret') {
    view = 'secret'
  } else if (manualView === 'servers') {
    view = 'servers'
  } else {
    view = 'home'
  }

  showView(view)

  if (view === 'secret') updateSecretView()
  else if (view === 'home') renderWalletList(state)
  else if (view === 'wallet') renderWalletDetail(state)
  else if (view === 'register') renderRegister(state)
  else if (view === 'servers') renderServers(state)
  else if (view === 'sign') renderSignList(state)
}

function showView(view: View): void {
  if (currentView === 'secret' && view !== 'secret') clearSecretValues()
  if (currentView === 'register' && view !== 'register') leaveRegister()
  if (currentView === 'wallet' && view !== 'wallet') clearAddKeyForm()
  if (view !== 'home') clearExport()
  for (const v of VIEWS) {
    hide($(`view-${v}`), v !== view)
  }
  currentView = view
}

// ---------------------------------------------------------------------------
// Secret creation / import
// ---------------------------------------------------------------------------

function secretDomain(): string {
  const state = lastState
  if (!state) return 'awiki.ai'
  const server =
    state.servers.find((s) => s.id === state.defaultServerId) ?? state.servers[0]
  return server?.didDomain || 'awiki.ai'
}

function showSecret(mode: 'create' | 'add'): void {
  secretMode = mode
  manualView = 'secret'
  detailWalletId = null
  regWalletId = null
  resetSecretForm()
  void render()
}

function resetSecretForm(): void {
  generatedMnemonic = ''
  importedKey = null
  secretSource = 'generate'
  secretStep = 'source'

  textarea('mnemonic-display').value = ''
  textarea('import-mnemonic').value = ''
  textarea('import-key').value = ''
  input('mnemonic-saved').checked = false
  input('key-confirm').checked = false
  input('secret-handle').value = ''
  input('secret-label').value = ''
  input('wallet-password').value = ''
  clear($('copy-hint'))
  clear($('mnemonic-err'))
  clear($('key-err'))
  clear($('recall-fields'))
  clear($('recall-err'))
  clear($('secret-err'))
  clear($('secret-full-handle'))
  clear($('secret-did-preview'))
  hide($('generate-box'), true)
  hide($('key-preview'), true)
  hide($('secret-did-preview'), true)
  switchSource('generate')
}

function clearSecretValues(): void {
  resetSecretForm()
}

function switchSource(source: SecretSource): void {
  secretSource = source
  for (const tab of document.querySelectorAll<HTMLButtonElement>('#source-tabs .tab')) {
    tab.classList.toggle('active', tab.dataset.source === source)
  }
  hide($('source-generate'), source !== 'generate')
  hide($('source-mnemonic'), source !== 'mnemonic')
  hide($('source-key'), source !== 'key')
  if (source !== 'generate') {
    generatedMnemonic = ''
    textarea('mnemonic-display').value = ''
    hide($('generate-box'), true)
    clear($('copy-hint'))
  }
  if (source !== 'mnemonic') {
    textarea('import-mnemonic').value = ''
    input('mnemonic-saved').checked = false
    clear($('mnemonic-err'))
  }
  if (source !== 'key') {
    textarea('import-key').value = ''
    input('key-confirm').checked = false
    importedKey = null
    hide($('key-preview'), true)
    clear($('key-err'))
  }
  clear($('secret-err'))
  secretStepTo('source')
}

function secretStepTo(step: SecretStep): void {
  secretStep = step
  hide($('secret-step-source'), step !== 'source')
  hide($('secret-step-recall'), step !== 'recall')
  hide($('secret-step-meta'), step !== 'meta')
  if (step === 'meta') updateSecretHandlePreview()
}

function updateSecretView(): void {
  const creating = secretMode === 'create'
  $('secret-title').textContent = creating ? '创建钱包' : '添加钱包'
  $('secret-intro').textContent = creating
    ? '钱包只管理 Ed25519 身份密钥和 DID；不会生成或保存任何通信/E2EE 密钥。'
    : '新钱包会使用当前已解锁的全局密码加密；所有钱包共享同一个密码。'
  hide($('password-field'), !creating)
  hide($('btn-secret-cancel'), creating)
  hide($('btn-secret-back'), !creating)
  $('btn-secret-submit').textContent = creating ? '创建并加密' : '添加钱包'
  $('secret-handle-label').textContent = `Handle（可选，例如 alice；DID 域 ${secretDomain()}）`
  if (secretStep === 'meta') updateSecretHandlePreview()
}

function copyText(text: string, hint: HTMLElement, okText = '已复制'): void {
  const done = (ok: boolean) => {
    hint.textContent = ok ? okText : '复制失败，请手动选择文本'
  }
  try {
    void navigator.clipboard.writeText(text).then(
      () => done(true),
      () => done(false),
    )
  } catch {
    done(false)
  }
}

function pickRecallPositions(count: number, total: number): number[] {
  const pool = Array.from({ length: total }, (_, i) => i)
  for (let i = pool.length - 1; i > 0; i -= 1) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1)
    ;[pool[i], pool[j]] = [pool[j], pool[i]]
  }
  return pool.slice(0, count).sort((a, b) => a - b)
}

function renderRecallFields(): void {
  const fields = $('recall-fields')
  clear(fields)
  const words = generatedMnemonic.split(/\s+/).filter(Boolean)
  const positions = pickRecallPositions(3, words.length)
  for (const pos of positions) {
    const label = document.createElement('label')
    label.className = 'field recall-field'
    const span = document.createElement('span')
    span.textContent = `第 ${pos + 1} 个词`
    const el = document.createElement('input')
    el.type = 'text'
    el.autocomplete = 'off'
    el.spellcheck = false
    el.dataset.pos = String(pos)
    label.append(span, el)
    fields.append(label)
  }
  clear($('recall-err'))
  secretStepTo('recall')
}

function normalizeMnemonic(value: string): string {
  return value.trim().toLowerCase().split(/\s+/).filter(Boolean).join(' ')
}

function updateSecretHandlePreview(): void {
  const domain = secretDomain()
  const raw = input('secret-handle').value.trim()
  const fullEl = $('secret-full-handle')
  const didEl = $('secret-did-preview')

  if (!raw) {
    fullEl.textContent = `留空可稍后注册；DID 域 ${domain}`
  } else {
    const parsed = localFromInput(raw, domain)
    fullEl.textContent = parsed.valid
      ? `将注册为 ${parsed.full}`
      : 'Handle 只能包含小写字母、数字和连字符（1–63 字符）'
  }

  if (!importedKey || !raw) {
    hide(didEl, true)
    didEl.textContent = ''
    return
  }
  const parsed = localFromInput(raw, domain)
  if (!parsed.valid) {
    hide(didEl, true)
    didEl.textContent = ''
    return
  }
  try {
    const identity = buildAwikiIdentity(parsed.full, importedKey.seed, domain)
    didEl.textContent = `公钥 ${multibaseEd25519(importedKey.publicKey)}\nDID ${identity.did}`
    hide(didEl, false)
  } catch (e) {
    didEl.textContent = e instanceof Error ? e.message : '无法预览 DID'
    hide(didEl, false)
  }
}

interface LocalHandle {
  local: string
  full: string
  valid: boolean
}

function localFromInput(raw: string, domain: string): LocalHandle {
  const value = raw.trim().toLowerCase()
  if (!value) return { local: '', full: '', valid: false }
  const suffix = `.${domain}`
  const local = value.endsWith(suffix) ? value.slice(0, -suffix.length) : value
  const valid = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(local)
  return { local, full: local ? `${local}.${domain}` : '', valid }
}

function previewImportedKey(): void {
  const raw = textarea('import-key').value.trim()
  const preview = $('key-preview')
  const err = $('key-err')
  if (!raw) {
    importedKey = null
    hide(preview, true)
    clear(err)
    return
  }
  try {
    const parsed = parseEd25519PrivateKey(raw)
    importedKey = parsed
    preview.textContent = `格式 ${parsed.format}\n公钥 ${multibaseEd25519(parsed.publicKey)}`
    hide(preview, false)
    clear(err)
  } catch (e) {
    importedKey = null
    hide(preview, true)
    err.textContent = e instanceof Error ? e.message : String(e)
  }
}

async function submitSecret(): Promise<void> {
  const err = $('secret-err')
  clear(err)
  const creating = secretMode === 'create'
  const password = input('wallet-password').value
  if (creating && password.length < 8) {
    err.textContent = '密码至少 8 位'
    return
  }

  const handleRaw = input('secret-handle').value.trim()
  if (handleRaw) {
    const parsed = localFromInput(handleRaw, secretDomain())
    if (!parsed.valid) {
      err.textContent = 'Handle 只能包含小写字母、数字和连字符（1–63 字符）'
      return
    }
  }
  const label = input('secret-label').value.trim() || undefined
  const handle = handleRaw || undefined

  let mnemonic: string | null = null
  let privateKey: string | null = null

  if (secretSource === 'generate') {
    if (!generatedMnemonic) {
      err.textContent = '请先生成并备份助记词'
      return
    }
    mnemonic = generatedMnemonic
  } else if (secretSource === 'mnemonic') {
    mnemonic = normalizeMnemonic(textarea('import-mnemonic').value)
    if (!isValidMnemonic(mnemonic)) {
      err.textContent = '助记词不是合法的 BIP39 序列'
      return
    }
    if (!input('mnemonic-saved').checked) {
      err.textContent = '请先勾选“我已妥善保存这组助记词”'
      return
    }
  } else {
    privateKey = textarea('import-key').value.trim()
    try {
      parseEd25519PrivateKey(privateKey)
    } catch (e) {
      err.textContent = e instanceof Error ? e.message : String(e)
      return
    }
    if (!input('key-confirm').checked) {
      err.textContent = '请先确认这是 Ed25519 身份私钥并已妥善保存'
      return
    }
  }

  const button = $('btn-secret-submit') as HTMLButtonElement
  button.disabled = true
  try {
    let resp: ApiResponse
    if (creating) {
      resp = privateKey
        ? await send({
            type: 'anp-wallet/create-account',
            source: 'imported',
            privateKey,
            password,
            handle,
            label,
          })
        : await send({ type: 'anp-wallet/create-account', mnemonic: mnemonic!, password, handle, label })
    } else {
      resp = privateKey
        ? await send({ type: 'anp-wallet/add-wallet', source: 'imported', privateKey, handle, label })
        : await send({ type: 'anp-wallet/add-wallet', mnemonic: mnemonic!, handle, label })
    }
    if (resp.status === 'ok') {
      clearSecretValues()
      manualView = null
      detailWalletId = null
      regWalletId = null
      await render()
      return
    }
    err.textContent = typeof resp.error === 'string' ? resp.error : '操作失败'
    if (isLockedResponse(resp)) await render()
  } catch (e) {
    err.textContent = e instanceof Error ? e.message : String(e)
  } finally {
    button.disabled = false
  }
}

function cancelSecret(): void {
  clearSecretValues()
  manualView = null
  detailWalletId = null
  regWalletId = null
  void render()
}

// ---------------------------------------------------------------------------
// Home and wallet detail
// ---------------------------------------------------------------------------

function clearExport(): void {
  const box = $('export-box')
  box.textContent = ''
  hide(box, true)
  hide($('btn-copy-export'), true)
  $('btn-copy-export').textContent = '复制导出内容'
}

function renderWalletList(state: State): void {
  const account = state.account!
  const list = $('wallet-list')
  clear(list)
  const activeId = state.activeRef?.walletId ?? account.activeWalletId

  for (const wallet of account.wallets) {
    const li = document.createElement('li')
    const card = document.createElement('button')
    card.type = 'button'
    card.className = `wallet-card${wallet.id === activeId ? ' active' : ''}`

    const head = document.createElement('div')
    head.className = 'wallet-card-head'
    const title = document.createElement('strong')
    title.textContent = wallet.label
    head.append(title)
    head.append(tag(wallet.kind === 'imported' ? '导入私钥' : '助记词'))

    const h = document.createElement('div')
    h.className = 'wallet-card-handle'
    h.textContent = wallet.handle || '未注册 handle'

    const meta = document.createElement('div')
    meta.className = 'wallet-card-meta'
    meta.textContent = `${wallet.keys.length} 密钥 · ${wallet.keys.filter((k) => k.registered).length} 已绑定`

    const serverLine = document.createElement('div')
    serverLine.className = 'wallet-card-meta'
    serverLine.textContent = walletServerLabel(state, wallet)

    const primary = wallet.keys[wallet.primaryKeyIndex]
    const didLine = document.createElement('div')
    didLine.className = 'wallet-card-did mono'
    didLine.textContent = primary ? short(primary.did, 46) : '无主密钥'

    card.append(head, h, meta, serverLine, didLine)
    if (wallet.registered) card.append(tag('已注册', 'ok'))
    card.addEventListener('click', () => void goDetail(wallet.id))
    li.append(card)
    list.append(li)
  }

  const wallet = activeWallet(state)
  const exportBtn = $('btn-export') as HTMLButtonElement
  exportBtn.textContent = wallet?.kind === 'imported' ? '导出私钥' : '导出助记词'
  exportBtn.disabled = !wallet
  hide($('unlocked-row'), false)
}

async function goDetail(walletId: string): Promise<void> {
  const state = lastState
  if (!state) return
  try {
    const resp = await send({ type: 'anp-wallet/select-wallet', walletId })
    if (resp.status !== 'ok') {
      alert(typeof resp.error === 'string' ? resp.error : '无法切换到该钱包')
      return
    }
  } catch (e) {
    alert(e instanceof Error ? e.message : String(e))
    return
  }
  manualView = null
  regWalletId = null
  detailWalletId = walletId
  void render()
}

function goHome(): void {
  manualView = null
  detailWalletId = null
  regWalletId = null
  void render()
}

function renderWalletDetail(state: State): void {
  const wallet = walletById(state.account, detailWalletId)
  if (!wallet) {
    detailWalletId = null
    void render()
    return
  }
  const account = state.account!
  const primary = wallet.keys[wallet.primaryKeyIndex]
  $('wallet-label').textContent = wallet.label
  $('wallet-primary').textContent = primary ? `主 #${primary.index}` : '无主密钥'
  $('wallet-pill').textContent = `${wallet.keys.length} 密钥 · ${wallet.keys.filter((k) => k.registered).length} 已绑定`
  $('wallet-handle').textContent = wallet.handle
    ? `${wallet.handle} · DID 域 ${wallet.didDomain}`
    : `未注册 handle · DID 域 ${wallet.didDomain}`

  const badges = $('wallet-badges')
  clear(badges)
  badges.append(tag(wallet.kind === 'imported' ? '导入私钥' : '助记词'))
  badges.append(tag(walletServerLabel(state, wallet)))
  badges.append(tag(wallet.registered ? '已注册' : '未注册', wallet.registered ? 'ok' : 'warn'))

  const registerBtn = $('btn-wallet-register') as HTMLButtonElement
  registerBtn.disabled = Boolean(wallet.registered) || wallet.keys.length === 0
  registerBtn.textContent = wallet.registered ? '已注册' : '注册身份'

  const addKeyBtn = $('btn-add-key') as HTMLButtonElement
  addKeyBtn.textContent =
    wallet.kind === 'imported' ? '＋ 导入 Ed25519 私钥' : '＋ 派生新密钥'
  hide($('add-key-form'), true)
  clear($('add-key-err'))
  textarea('add-key-input').value = ''

  const list = $('key-list')
  clear(list)
  wallet.keys.forEach((key, pos) => list.append(renderKey(state, wallet, key, pos)))

  const deleteWalletBtn = $('btn-wallet-delete') as HTMLButtonElement
  deleteWalletBtn.textContent =
    account.wallets.length === 1 ? '删除最后一个钱包（将锁定并清空账号）' : '删除这个钱包'
}

function renderKey(state: State, wallet: Wallet, key: StoredKey, pos: number): HTMLElement {
  const li = document.createElement('li')
  li.className = 'key-card'
  const isPrimary = pos === wallet.primaryKeyIndex
  const isActive =
    state.activeRef?.walletId === wallet.id && state.activeRef.keyIndex === pos
  const aggregate = effectiveMode(wallet) === 'aggregate'
  const canSetPrimary = !isPrimary && (aggregate || !wallet.registered)

  const head = document.createElement('div')
  head.className = 'key-head'
  const index = document.createElement('span')
  index.className = 'key-index'
  index.textContent = `密钥 #${key.index}`
  head.append(index)
  if (isPrimary) head.append(tag('主', 'primary'))
  if (isActive) head.append(tag('默认', 'ok'))
  if (key.registered) head.append(tag('已绑定', 'ok'))

  const kid = document.createElement('div')
  kid.className = 'key-id mono'
  kid.textContent = short(key.keyid, 58)

  const handle = document.createElement('div')
  handle.className = 'key-handle'
  handle.textContent = key.handle || '未注册 handle'

  const did = document.createElement('div')
  did.className = 'key-did mono'
  did.textContent = short(key.did, 58)

  const actions = document.createElement('div')
  actions.className = 'key-actions'

  if (canSetPrimary) {
    const b = document.createElement('button')
    b.textContent = '设为主密钥'
    b.addEventListener('click', async () => {
      b.disabled = true
      const resp = await send({ type: 'anp-wallet/set-primary', walletId: wallet.id, keyIndex: pos })
      if (resp.status !== 'ok') alert(typeof resp.error === 'string' ? resp.error : '设置失败')
      void render()
    })
    actions.append(b)
  }

  if (!isActive) {
    const b = document.createElement('button')
    b.textContent = '用于登录签名'
    b.addEventListener('click', async () => {
      b.disabled = true
      const resp = await send({ type: 'anp-wallet/select-active', walletId: wallet.id, keyIndex: pos })
      if (resp.status !== 'ok') alert(typeof resp.error === 'string' ? resp.error : '切换失败')
      void render()
    })
    actions.append(b)
  }

  if (!isPrimary && wallet.keys.length > 1) {
    const b = document.createElement('button')
    b.className = 'danger'
    b.textContent = '删除'
    b.addEventListener('click', async () => {
      if (!confirm(`删除密钥 #${key.index}？此操作不可恢复。`)) return
      if (!confirm(`再次确认删除密钥 #${key.index}。`)) return
      b.disabled = true
      const resp = await send({ type: 'anp-wallet/delete-key', walletId: wallet.id, keyIndex: pos })
      if (resp.status !== 'ok') alert(typeof resp.error === 'string' ? resp.error : '删除失败')
      void render()
    })
    actions.append(b)
  }

  li.append(head, kid, handle, did, actions)
  return li
}

function clearAddKeyForm(): void {
  hide($('add-key-form'), true)
  textarea('add-key-input').value = ''
  clear($('add-key-err'))
}

async function exportSecret(): Promise<void> {
  const resp = await send({ type: 'anp-wallet/export-secret' })
  const box = $('export-box')
  if (resp.status !== 'ok') {
    alert(typeof resp.error === 'string' ? resp.error : '导出失败')
    return
  }
  if (resp.kind === 'mnemonic' && typeof resp.mnemonic === 'string') {
    box.textContent = resp.mnemonic
  } else if (resp.kind === 'imported' && Array.isArray(resp.keys)) {
    const lines = (resp.keys as Array<{ index: number; privateKey: string }>).map(
      (k) => `#${k.index}: ${k.privateKey}`,
    )
    box.textContent = `导入私钥（base64url 32-byte seed）\n${lines.join('\n')}`
  } else {
    box.textContent = JSON.stringify(resp, null, 2)
  }
  hide(box, false)
  hide($('btn-copy-export'), false)
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

interface RegContext {
  state: State
  wallet: Wallet
  server: ServerConfig | null
  aggregate: boolean
  needsRebind: boolean
}

function regContext(): RegContext | null {
  const state = lastState
  if (!state?.account || !regWalletId) return null
  const wallet = walletById(state.account, regWalletId)
  if (!wallet) return null
  const aggregate = effectiveMode(wallet) === 'aggregate'
  const server = aggregate ? null : serverForWallet(state, wallet)
  const needsRebind = !aggregate && (!server || server.didDomain !== wallet.didDomain)
  return { state, wallet, server, aggregate, needsRebind }
}

function goRegister(walletId: string): void {
  regWalletId = walletId
  regDraft = null
  manualView = null
  void render()
}

function leaveRegister(): void {
  stopEmailPoll()
  regDraft = null
  const email = $('reg-email') as HTMLInputElement
  email.value = ''
  input('reg-handle').value = ''
  input('reg-invite').value = ''
  clear($('reg-status'))
  clear($('rebind-err'))
  setRegEmailStatus('', '')
}

function ensureRegDraft(wallet: Wallet): RegDraft {
  if (regDraft && regDraft.walletId === wallet.id) return regDraft
  const local = wallet.handle ? wallet.handle.split('.')[0] : ''
  regDraft = {
    walletId: wallet.id,
    handle: local,
    email: '',
    invite: '',
    verified: null,
    note: '',
  }
  return regDraft
}

function addSummaryRow(dl: HTMLElement, label: string, value: string): void {
  const dt = document.createElement('dt')
  dt.textContent = label
  const dd = document.createElement('dd')
  dd.textContent = value
  dl.append(dt, dd)
}

function renderRegister(state: State): void {
  const wallet = walletById(state.account, regWalletId)
  if (!wallet) {
    regWalletId = null
    void render()
    return
  }
  const aggregate = effectiveMode(wallet) === 'aggregate'
  const server = aggregate ? null : serverForWallet(state, wallet)
  const primary = wallet.keys[wallet.primaryKeyIndex]

  const summary = $('reg-summary')
  clear(summary)
  const dl = document.createElement('dl')
  addSummaryRow(dl, '钱包', wallet.label)
  addSummaryRow(dl, '来源', wallet.kind === 'imported' ? '导入私钥' : '助记词')
  addSummaryRow(dl, '模式', aggregate ? '旧聚合（兼容）' : '单 DID（did_document）')
  addSummaryRow(
    dl,
    '服务器',
    aggregate
      ? 'localhost（旧本地 open-server）'
      : server
        ? `${server.label} · ${server.didDomain}`
        : '未绑定 / 已移除',
  )
  if (primary) addSummaryRow(dl, '主 DID', primary.did)
  summary.append(dl)

  const done = $('reg-done')
  const form = $('reg-form')
  const fields = $('reg-fields')
  const rebindBox = $('reg-rebind-box')

  if (wallet.registered) {
    hide(done, false)
    hide(form, true)
    $('reg-done-handle').textContent = wallet.handle || '—'
    $('reg-done-did').textContent = primary?.did || '—'
    $('reg-done-mode').textContent = aggregate ? '旧聚合 ad.json' : '单 DID 文档'
    stopEmailPoll()
    return
  }

  hide(done, true)
  hide(form, false)

  const needsRebind = !aggregate && (!server || server.didDomain !== wallet.didDomain)
  if (needsRebind) {
    hide(fields, true)
    hide(rebindBox, false)
    const sel = select('reg-rebind-server')
    clear(sel)
    const servers = state.servers ?? []
    for (const s of servers) {
      const opt = document.createElement('option')
      opt.value = s.id
      opt.textContent = `${s.label} · ${s.didDomain}`
      sel.append(opt)
    }
    const preferred =
      (wallet.serverId && servers.some((s) => s.id === wallet.serverId) && wallet.serverId) ||
      state.defaultServerId ||
      servers[0]?.id
    if (preferred) sel.value = preferred
    ;($('btn-rebind') as HTMLButtonElement).disabled = servers.length === 0
    clear($('rebind-err'))
    stopEmailPoll()
    return
  }

  hide(rebindBox, true)
  hide(fields, false)
  const draft = ensureRegDraft(wallet)
  clear($('reg-status'))

  const emailField = $('reg-email-field')
  const emailActions = $('reg-email-actions')
  const inviteField = $('reg-invite-field')
  const verifyBtn = $('btn-verify-existing')
  hide(emailField, aggregate)
  hide(emailActions, aggregate)
  hide(inviteField, aggregate)
  hide(verifyBtn, aggregate)

  $('reg-note').textContent = aggregate
    ? '旧聚合模式：提交 handle 级别的 ad.json；邮箱可选，不启用邮箱验证。'
    : '注册会把主 DID 绑定到这个 handle；邮箱只用于本次注册，不会保存。'

  const handleEl = input('reg-handle')
  if (document.activeElement !== handleEl) handleEl.value = draft.handle
  const emailEl = input('reg-email')
  if (document.activeElement !== emailEl) emailEl.value = draft.email
  const inviteEl = input('reg-invite')
  if (document.activeElement !== inviteEl) inviteEl.value = draft.invite

  updateRegHandlePreview()
  if (draft.note) {
    setRegEmailStatus(draft.note, draft.verified === true ? 'ok' : draft.verified === false ? 'warn' : 'muted')
  } else {
    setRegEmailStatus('', '')
  }
  updateRegAvailability()
}

function setRegEmailStatus(text: string, kind: string): void {
  const box = $('reg-email-status')
  box.textContent = text
  box.className = `status-box${kind ? ` ${kind}` : ''}`
  hide(box, !text)
}

function regDomain(ctx: RegContext): string {
  return ctx.aggregate ? 'localhost' : ctx.server?.didDomain ?? ctx.wallet.didDomain
}

function regHandleInput(): LocalHandle {
  const ctx = regContext()
  return localFromInput(input('reg-handle').value, ctx ? regDomain(ctx) : 'awiki.ai')
}

function updateRegHandlePreview(): void {
  const ctx = regContext()
  if (!ctx) return
  const raw = input('reg-handle').value.trim()
  const parsed = localFromInput(raw, regDomain(ctx))
  const el = $('reg-full-handle')
  if (!raw) el.textContent = `完整 handle：${regDomain(ctx)}（填写后显示）`
  else if (!parsed.valid) el.textContent = 'Handle 只能包含小写字母、数字和连字符（1–63 字符）'
  else el.textContent = `完整 handle：${parsed.full}`
  updateRegAvailability()
}

function emailValid(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
}

function updateRegAvailability(): void {
  const ctx = regContext()
  if (!ctx || ctx.wallet.registered || ctx.needsRebind) return
  const draft = ensureRegDraft(ctx.wallet)
  const parsed = regHandleInput()
  const button = $('btn-register') as HTMLButtonElement
  const email = input('reg-email').value.trim()
  let can = parsed.valid && ctx.wallet.keys.length > 0
  if (!ctx.aggregate) {
    can = can && emailValid(email)
    if (ctx.server?.didDomain === 'awiki.ai') can = can && draft.verified === true
  }
  button.disabled = !can
}

function resetRegVerification(): void {
  if (!regDraft) return
  regDraft.verified = null
  regDraft.note = ''
  stopEmailPoll()
  setRegEmailStatus('', '')
  clear($('reg-status'))
}

async function checkEmailStatus(silent: boolean): Promise<void> {
  const ctx = regContext()
  if (!ctx || ctx.aggregate || !ctx.server) return
  const draft = ensureRegDraft(ctx.wallet)
  const parsed = regHandleInput()
  const email = input('reg-email').value.trim()
  if (!parsed.valid || !emailValid(email)) {
    if (!silent) setRegEmailStatus('请先填写合法的 handle 和邮箱', 'err')
    return
  }
  try {
    const resp = await send({
      type: 'anp-wallet/email-status',
      serverId: ctx.server.id,
      email,
      fullHandle: parsed.full,
    })
    if (resp.status === 'ok') {
      draft.verified = resp.verified === true
      const at = typeof resp.verifiedAt === 'string' ? `（${resp.verifiedAt}）` : ''
      draft.note = draft.verified
        ? `邮箱已验证${at}`
        : '邮箱尚未验证，请点击邮件中的激活链接'
      setRegEmailStatus(draft.note, draft.verified ? 'ok' : 'warn')
      if (draft.verified) stopEmailPoll()
    } else if (resp.status === 'unsupported') {
      draft.verified = null
      draft.note = '该服务器未启用邮箱验证，可直接注册'
      setRegEmailStatus(draft.note, 'warn')
      stopEmailPoll()
    } else if (!silent) {
      draft.verified = null
      draft.note = typeof resp.error === 'string' ? resp.error : '邮箱状态查询失败'
      setRegEmailStatus(draft.note, 'err')
    }
  } catch (e) {
    if (!silent) setRegEmailStatus(e instanceof Error ? e.message : String(e), 'err')
  }
  updateRegAvailability()
}

async function sendEmailVerification(): Promise<void> {
  const ctx = regContext()
  if (!ctx || ctx.aggregate || !ctx.server) return
  const parsed = regHandleInput()
  const email = input('reg-email').value.trim()
  if (!parsed.valid || !emailValid(email)) {
    setRegEmailStatus('请先填写合法的 handle 和邮箱', 'err')
    return
  }
  const draft = ensureRegDraft(ctx.wallet)
  const btn = $('btn-email-send') as HTMLButtonElement
  btn.disabled = true
  try {
    const resp = await send({
      type: 'anp-wallet/email-send',
      serverId: ctx.server.id,
      email,
      fullHandle: parsed.full,
    })
    if (resp.status === 'ok') {
      draft.verified = null
      draft.note = '验证邮件已发送，请到邮箱点击激活链接；本页会自动检查 3 分钟。'
      setRegEmailStatus(draft.note, 'muted')
      startEmailPoll(ctx.wallet.id)
    } else if (resp.status === 'unsupported') {
      draft.verified = null
      draft.note = '该服务器未启用邮箱验证，可直接注册'
      setRegEmailStatus(draft.note, 'warn')
      stopEmailPoll()
    } else {
      draft.note = typeof resp.error === 'string' ? resp.error : '发送验证邮件失败'
      setRegEmailStatus(draft.note, 'err')
    }
  } catch (e) {
    setRegEmailStatus(e instanceof Error ? e.message : String(e), 'err')
  } finally {
    btn.disabled = false
    updateRegAvailability()
  }
}

function startEmailPoll(walletId: string): void {
  stopEmailPoll()
  emailPollWalletId = walletId
  emailPollUntil = Date.now() + 3 * 60 * 1000
  emailPollTimer = window.setInterval(() => {
    if (Date.now() > emailPollUntil) {
      const draft = regDraft
      if (draft && draft.walletId === emailPollWalletId && draft.verified !== true) {
        draft.note = '自动检查已结束，可点击“检查验证状态”手动重试'
        setRegEmailStatus(draft.note, 'warn')
      }
      stopEmailPoll()
      return
    }
    if (currentView !== 'register') {
      stopEmailPoll()
      return
    }
    if (!regDraft || regDraft.walletId !== emailPollWalletId) {
      stopEmailPoll()
      return
    }
    void checkEmailStatus(true)
  }, 5000)
}

function stopEmailPoll(): void {
  if (emailPollTimer != null) {
    window.clearInterval(emailPollTimer)
    emailPollTimer = null
  }
  emailPollWalletId = null
  emailPollUntil = 0
}

async function submitRegister(): Promise<void> {
  const ctx = regContext()
  if (!ctx) return
  const status = $('reg-status')
  clear(status)
  const parsed = regHandleInput()
  if (!parsed.valid) {
    status.textContent = '请填写合法的 handle'
    return
  }
  const draft = ensureRegDraft(ctx.wallet)
  let email: string | undefined
  let inviteCode: string | undefined
  if (!ctx.aggregate) {
    if (!ctx.server) {
      status.textContent = '钱包未绑定可用服务器，请先更换服务器'
      return
    }
    email = input('reg-email').value.trim()
    if (!emailValid(email)) {
      status.textContent = '请填写合法邮箱'
      return
    }
    if (ctx.server.didDomain === 'awiki.ai' && draft.verified !== true) {
      status.textContent = '请先完成邮箱验证'
      return
    }
    inviteCode = input('reg-invite').value.trim() || undefined
  }

  const btn = $('btn-register') as HTMLButtonElement
  btn.disabled = true
  try {
    const resp = await send({
      type: 'anp-wallet/register',
      walletId: ctx.wallet.id,
      handle: parsed.local,
      email,
      inviteCode,
    })
    if (resp.status === 'ok') {
      regDraft = null
      stopEmailPoll()
      input('reg-email').value = ''
      setRegEmailStatus('', '')
      await render()
      return
    }
    status.textContent = typeof resp.error === 'string' ? resp.error : '注册失败'
    if (isLockedResponse(resp)) await render()
  } catch (e) {
    status.textContent = e instanceof Error ? e.message : String(e)
  } finally {
    btn.disabled = false
    updateRegAvailability()
  }
}

async function verifyExisting(): Promise<void> {
  const ctx = regContext()
  if (!ctx) return
  const parsed = regHandleInput()
  if (!parsed.valid) {
    $('reg-status').textContent = '请填写合法的 handle'
    return
  }
  if (ctx.aggregate) return
  const btn = $('btn-verify-existing') as HTMLButtonElement
  btn.disabled = true
  clear($('reg-status'))
  try {
    const resp = await send({
      type: 'anp-wallet/verify-existing',
      walletId: ctx.wallet.id,
      handle: parsed.local,
    })
    if (resp.status === 'ok') {
      regDraft = null
      stopEmailPoll()
      input('reg-email').value = ''
      setRegEmailStatus('', '')
      await render()
      return
    }
    $('reg-status').textContent = typeof resp.error === 'string' ? resp.error : '验证失败'
    if (isLockedResponse(resp)) await render()
  } catch (e) {
    $('reg-status').textContent = e instanceof Error ? e.message : String(e)
  } finally {
    btn.disabled = false
    updateRegAvailability()
  }
}

async function rebindServer(): Promise<void> {
  const ctx = regContext()
  if (!ctx) return
  const serverId = select('reg-rebind-server').value
  if (!serverId) {
    $('rebind-err').textContent = '请选择服务器'
    return
  }
  const btn = $('btn-rebind') as HTMLButtonElement
  btn.disabled = true
  clear($('rebind-err'))
  try {
    const resp = await send({
      type: 'anp-wallet/rebind-server',
      walletId: ctx.wallet.id,
      serverId,
    })
    if (resp.status === 'ok') {
      regDraft = null
      stopEmailPoll()
      await render()
      return
    }
    $('rebind-err').textContent = typeof resp.error === 'string' ? resp.error : '更换服务器失败'
    if (isLockedResponse(resp)) await render()
  } catch (e) {
    $('rebind-err').textContent = e instanceof Error ? e.message : String(e)
  } finally {
    btn.disabled = false
  }
}

// ---------------------------------------------------------------------------
// Servers
// ---------------------------------------------------------------------------

function showServers(): void {
  manualView = 'servers'
  detailWalletId = null
  regWalletId = null
  void render()
}

function renderServers(state: State): void {
  const list = $('server-list')
  clear(list)
  const servers = state.servers ?? []
  for (const server of servers) {
    const li = document.createElement('li')
    li.className = 'server-item'

    const head = document.createElement('div')
    head.className = 'server-head'
    const name = document.createElement('strong')
    name.textContent = server.label
    head.append(name)
    if (server.builtin) head.append(tag('内置', 'muted'))
    if (server.id === state.defaultServerId) head.append(tag('默认', 'ok'))

    const rpc = document.createElement('div')
    rpc.className = 'server-line mono'
    rpc.textContent = server.rpcBase

    const domain = document.createElement('div')
    domain.className = 'server-line'
    domain.textContent = `DID 域：${server.didDomain}${server.registerMode === 'aggregate' ? ' · 旧聚合' : ''}`

    const actions = document.createElement('div')
    actions.className = 'key-actions'

    if (server.id !== state.defaultServerId) {
      const b = document.createElement('button')
      b.textContent = '设为默认'
      b.addEventListener('click', async () => {
        b.disabled = true
        const resp = await send({ type: 'anp-wallet/set-default-server', serverId: server.id })
        if (resp.status !== 'ok') alert(typeof resp.error === 'string' ? resp.error : '设置失败')
        void render()
      })
      actions.append(b)
    }

    const test = document.createElement('button')
    test.textContent = '测试'
    const result = document.createElement('div')
    result.className = 'server-test'
    test.addEventListener('click', async () => {
      test.disabled = true
      result.textContent = '测试中…'
      try {
        const resp = await send({ type: 'anp-wallet/test-server', serverId: server.id })
        if (resp.status === 'ok') {
          result.textContent = `✓ ${resp.didDomain}${resp.source === 'fallback' ? '（使用内置快照）' : ''}`
          result.className = 'server-test ok'
        } else {
          result.textContent = `✗ ${typeof resp.error === 'string' ? resp.error : '测试失败'}`
          result.className = 'server-test err'
        }
      } catch (e) {
        result.textContent = `✗ ${e instanceof Error ? e.message : String(e)}`
        result.className = 'server-test err'
      } finally {
        test.disabled = false
      }
    })
    actions.append(test)

    if (!server.builtin) {
      const b = document.createElement('button')
      b.className = 'danger'
      b.textContent = '删除'
      b.addEventListener('click', async () => {
        if (!confirm(`删除服务器“${server.label}”？已绑定的钱包仍可签名，但不能再用它注册。`)) return
        b.disabled = true
        const resp = await send({ type: 'anp-wallet/remove-server', serverId: server.id })
        if (resp.status !== 'ok') alert(typeof resp.error === 'string' ? resp.error : '删除失败')
        void render()
      })
      actions.append(b)
    }

    li.append(head, rpc, domain, actions, result)
    list.append(li)
  }
}

function permissionOrigin(rpcBase: string): string {
  return `${new URL(rpcBase).origin}/*`
}

function requestOriginPermission(origin: string): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      if (!chrome.permissions?.request) {
        resolve(true)
        return
      }
      chrome.permissions.request({ origins: [origin] }, (granted) => {
        if (chrome.runtime.lastError) resolve(false)
        else resolve(Boolean(granted))
      })
    } catch {
      resolve(false)
    }
  })
}

async function addServer(): Promise<void> {
  const err = $('server-err')
  clear(err)
  const raw = input('server-rpc').value.trim()
  const domain = input('server-domain').value.trim()
  const label = input('server-label').value.trim() || undefined
  if (!raw) {
    err.textContent = '请填写 RPC 根 URL'
    return
  }
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    err.textContent = 'RPC 根 URL 不合法'
    return
  }
  if (url.protocol !== 'https:') {
    err.textContent = '自定义服务器仅支持 HTTPS'
    return
  }
  if (url.username || url.password || url.search || url.hash) {
    err.textContent = 'RPC 根 URL 不能包含用户名、密码、查询参数或片段'
    return
  }
  if (!domain) {
    err.textContent = '请填写 DID 域名'
    return
  }
  const rpcBase = url.origin + (url.pathname.replace(/\/+$/, '') === '/' ? '' : url.pathname.replace(/\/+$/, ''))
  const btn = $('btn-add-server') as HTMLButtonElement
  btn.disabled = true
  try {
    const granted = await requestOriginPermission(permissionOrigin(rpcBase))
    if (!granted) {
      err.textContent = '未获得该服务器的访问授权，未保存'
      return
    }
    const resp = await send({
      type: 'anp-wallet/add-server',
      rpcBase,
      didDomain: domain,
      label,
    })
    if (resp.status !== 'ok') {
      err.textContent = typeof resp.error === 'string' ? resp.error : '添加服务器失败'
      return
    }
    input('server-rpc').value = ''
    input('server-domain').value = ''
    input('server-label').value = ''
    await render()
  } catch (e) {
    err.textContent = e instanceof Error ? e.message : String(e)
  } finally {
    btn.disabled = false
  }
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

function renderSignList(state: State): void {
  const account = state.account!
  const list = $('sign-list')
  clear(list)
  for (const p of state.pending) {
    const li = document.createElement('li')
    li.className = 'sign-card'
    const head = document.createElement('div')
    head.className = 'sign-head'
    const title = document.createElement('strong')
    title.textContent = '签名登录请求'
    head.append(title, tag(p.pageOrigin || '未知来源', 'muted'))

    const meta = document.createElement('div')
    meta.className = 'sign-meta'
    meta.textContent = `${p.method} ${short(p.url, 72)}`

    const preview = document.createElement('div')
    preview.className = 'sign-body mono'
    preview.textContent = short(p.bodyPreview || '（空 body）', 180)

    const sel = document.createElement('select')
    sel.className = 'sign-key'
    let any = false
    for (const w of account.wallets) {
      w.keys.forEach((k, pos) => {
        any = true
        const opt = document.createElement('option')
        opt.value = `${w.id}|${pos}`
        opt.textContent = `${w.label} · #${k.index}${k.handle ? ` (${k.handle})` : ''}`
        if (state.activeRef?.walletId === w.id && state.activeRef.keyIndex === pos) {
          opt.selected = true
        }
        sel.append(opt)
      })
    }

    const actions = document.createElement('div')
    actions.className = 'row'
    const reject = document.createElement('button')
    reject.textContent = '拒绝'
    reject.addEventListener('click', async () => {
      reject.disabled = true
      await send({ type: 'anp-wallet/reject', id: p.id })
      void render()
    })

    const approve = document.createElement('button')
    approve.className = 'primary'
    approve.textContent = '批准并签名'
    approve.disabled = !any
    approve.addEventListener('click', async () => {
      const [walletId, keyRaw] = sel.value.split('|')
      const keyIndex = Number(keyRaw)
      if (!walletId || !Number.isInteger(keyIndex)) return
      approve.disabled = true
      try {
        const resp = await send({
          type: 'anp-wallet/approve',
          id: p.id,
          sel: { walletId, keyIndex },
        })
        if (resp.status !== 'ok') alert(typeof resp.error === 'string' ? resp.error : '签名失败')
      } catch (e) {
        alert(e instanceof Error ? e.message : String(e))
      }
      void render()
    })
    actions.append(reject, approve)

    li.append(head, meta, preview, sel, actions)
    list.append(li)
  }
}

// ---------------------------------------------------------------------------
// Wire events
// ---------------------------------------------------------------------------

function wireEvents(): void {
  for (const tab of document.querySelectorAll<HTMLButtonElement>('#source-tabs .tab')) {
    tab.addEventListener('click', () => {
      const source = tab.dataset.source as SecretSource | undefined
      if (source === 'generate' || source === 'mnemonic' || source === 'key') switchSource(source)
    })
  }

  $('btn-generate').addEventListener('click', () => {
    generatedMnemonic = generateMnemonicPhrase(256)
    textarea('mnemonic-display').value = generatedMnemonic
    hide($('generate-box'), false)
    clear($('copy-hint'))
  })

  $('btn-copy-mnemonic').addEventListener('click', () => {
    if (!generatedMnemonic) return
    copyText(generatedMnemonic, $('copy-hint'), '助记词已复制')
  })

  $('btn-generate-next').addEventListener('click', () => {
    if (!generatedMnemonic) return
    renderRecallFields()
  })

  $('btn-recall-back').addEventListener('click', () => secretStepTo('source'))

  $('btn-recall-next').addEventListener('click', () => {
    const words = generatedMnemonic.split(/\s+/).filter(Boolean)
    const inputs = document.querySelectorAll<HTMLInputElement>('#recall-fields input')
    for (const el of inputs) {
      const pos = Number(el.dataset.pos)
      const answer = el.value.trim().toLowerCase()
      if (answer !== words[pos]) {
        $('recall-err').textContent = `第 ${pos + 1} 个词不正确`
        return
      }
    }
    clear($('recall-fields'))
    secretStepTo('meta')
  })

  $('btn-mnemonic-next').addEventListener('click', () => {
    const mnemonic = normalizeMnemonic(textarea('import-mnemonic').value)
    if (!isValidMnemonic(mnemonic)) {
      $('mnemonic-err').textContent = '助记词不是合法的 BIP39 序列'
      return
    }
    if (!input('mnemonic-saved').checked) {
      $('mnemonic-err').textContent = '请先勾选“我已妥善保存这组助记词”'
      return
    }
    clear($('mnemonic-err'))
    secretStepTo('meta')
  })

  textarea('import-key').addEventListener('input', previewImportedKey)
  $('btn-key-next').addEventListener('click', () => {
    previewImportedKey()
    if (!importedKey) {
      $('key-err').textContent = '请先输入可识别的 Ed25519 身份私钥'
      return
    }
    if (!input('key-confirm').checked) {
      $('key-err').textContent = '请先确认这是 Ed25519 身份私钥并已妥善保存'
      return
    }
    secretStepTo('meta')
  })

  input('secret-handle').addEventListener('input', updateSecretHandlePreview)
  $('btn-secret-submit').addEventListener('click', () => void submitSecret())
  $('btn-secret-back').addEventListener('click', cancelSecret)
  $('btn-secret-cancel').addEventListener('click', cancelSecret)

  $('btn-unlock').addEventListener('click', async () => {
    const password = input('unlock-password').value
    const err = $('unlock-err')
    clear(err)
    if (!password) {
      err.textContent = '请输入密码'
      return
    }
    const btn = $('btn-unlock') as HTMLButtonElement
    btn.disabled = true
    try {
      const resp = await send({ type: 'anp-wallet/unlock', password })
      if (resp.status === 'ok') {
        input('unlock-password').value = ''
        await render()
      } else {
        err.textContent = typeof resp.error === 'string' ? resp.error : '解锁失败'
      }
    } catch (e) {
      err.textContent = e instanceof Error ? e.message : String(e)
    } finally {
      btn.disabled = false
    }
  })

  input('unlock-password').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') ($('btn-unlock') as HTMLButtonElement).click()
  })

  $('btn-add-wallet').addEventListener('click', () => showSecret('add'))
  $('btn-lock').addEventListener('click', async () => {
    await send({ type: 'anp-wallet/lock' })
    manualView = null
    detailWalletId = null
    regWalletId = null
    regDraft = null
    stopEmailPoll()
    clearExport()
    await render()
  })
  $('btn-export').addEventListener('click', () => void exportSecret())
  $('btn-copy-export').addEventListener('click', () => {
    const text = $('export-box').textContent || ''
    if (!text) return
    const btn = $('btn-copy-export')
    navigator.clipboard.writeText(text).then(
      () => {
        btn.textContent = '已复制'
        window.setTimeout(() => {
          btn.textContent = '复制导出内容'
        }, 1500)
      },
      () => {
        btn.textContent = '复制失败，请手动选择'
      },
    )
  })

  $('btn-servers').addEventListener('click', showServers)
  $('btn-servers-back').addEventListener('click', goHome)
  $('btn-add-server').addEventListener('click', () => void addServer())

  $('btn-wallet-back').addEventListener('click', goHome)
  $('btn-wallet-rename').addEventListener('click', async () => {
    const wallet = walletById(lastState?.account ?? null, detailWalletId)
    if (!wallet) return
    const label = prompt('钱包名称', wallet.label)?.trim()
    if (!label) return
    const resp = await send({ type: 'anp-wallet/rename-wallet', walletId: wallet.id, label })
    if (resp.status !== 'ok') alert(typeof resp.error === 'string' ? resp.error : '重命名失败')
    void render()
  })

  $('btn-wallet-register').addEventListener('click', () => {
    if (detailWalletId) goRegister(detailWalletId)
  })

  $('btn-add-key').addEventListener('click', async () => {
    const wallet = walletById(lastState?.account ?? null, detailWalletId)
    if (!wallet) return
    if (wallet.kind === 'imported') {
      hide($('add-key-form'), false)
      textarea('add-key-input').focus()
      return
    }
    const resp = await send({ type: 'anp-wallet/add-key', walletId: wallet.id })
    if (resp.status !== 'ok') alert(typeof resp.error === 'string' ? resp.error : '派生失败')
    void render()
  })

  $('btn-add-key-cancel').addEventListener('click', clearAddKeyForm)
  $('btn-add-key-submit').addEventListener('click', async () => {
    const wallet = walletById(lastState?.account ?? null, detailWalletId)
    if (!wallet) return
    const privateKey = textarea('add-key-input').value.trim()
    const err = $('add-key-err')
    clear(err)
    if (!privateKey) {
      err.textContent = '请粘贴 Ed25519 私钥'
      return
    }
    const btn = $('btn-add-key-submit') as HTMLButtonElement
    btn.disabled = true
    try {
      const resp = await send({
        type: 'anp-wallet/add-key',
        walletId: wallet.id,
        privateKey,
      })
      if (resp.status === 'ok') {
        clearAddKeyForm()
        await render()
      } else {
        err.textContent = typeof resp.error === 'string' ? resp.error : '导入失败'
        if (isLockedResponse(resp)) await render()
      }
    } catch (e) {
      err.textContent = e instanceof Error ? e.message : String(e)
    } finally {
      btn.disabled = false
    }
  })

  $('btn-wallet-delete').addEventListener('click', async () => {
    const wallet = walletById(lastState?.account ?? null, detailWalletId)
    if (!wallet) return
    const last = (lastState?.account?.wallets.length ?? 0) <= 1
    if (!confirm(`删除钱包“${wallet.label}”？请先确认已备份密钥。`)) return
    if (!confirm(last ? '这是最后一个钱包，删除后会锁定并清空账号。继续？' : '再次确认删除。')) return
    const resp = await send({ type: 'anp-wallet/delete-wallet', walletId: wallet.id })
    if (resp.status !== 'ok') {
      alert(typeof resp.error === 'string' ? resp.error : '删除失败')
      return
    }
    detailWalletId = null
    regWalletId = null
    regDraft = null
    await render()
  })

  $('btn-register-back').addEventListener('click', () => {
    regWalletId = null
    regDraft = null
    stopEmailPoll()
    void render()
  })

  input('reg-handle').addEventListener('input', () => {
    const ctx = regContext()
    if (ctx) {
      const draft = ensureRegDraft(ctx.wallet)
      draft.handle = input('reg-handle').value.trim()
    }
    resetRegVerification()
    updateRegHandlePreview()
  })

  input('reg-email').addEventListener('input', () => {
    const ctx = regContext()
    if (ctx) {
      const draft = ensureRegDraft(ctx.wallet)
      draft.email = input('reg-email').value.trim()
    }
    resetRegVerification()
    updateRegAvailability()
  })

  input('reg-invite').addEventListener('input', () => {
    const ctx = regContext()
    if (ctx) ensureRegDraft(ctx.wallet).invite = input('reg-invite').value.trim()
  })

  input('reg-email').addEventListener('blur', () => {
    const ctx = regContext()
    if (!ctx || ctx.aggregate) return
    if (regHandleInput().valid && emailValid(input('reg-email').value.trim())) {
      void checkEmailStatus(true)
    }
  })

  $('btn-email-send').addEventListener('click', () => void sendEmailVerification())
  $('btn-email-check').addEventListener('click', () => void checkEmailStatus(false))
  $('btn-register').addEventListener('click', () => void submitRegister())
  $('btn-verify-existing').addEventListener('click', () => void verifyExisting())
  $('btn-rebind').addEventListener('click', () => void rebindServer())
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

wireEvents()
void render()
