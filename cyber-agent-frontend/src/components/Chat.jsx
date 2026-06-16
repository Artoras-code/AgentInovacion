import { useState, useRef, useEffect } from 'react'
import axios from 'axios'
import './Chat.css'

const PIXEL_BORDER = {
  border: '4px solid #00ff41',
  boxShadow: '4px 4px 0px #003d0f',
}

export default function Chat() {
  const [messages, setMessages] = useState([
    {
      role: 'agent',
      text: '> CYBER_AGENT v1.0 INICIADO...\n> Listo para analizar amenazas.\n> Escribe tu consulta para comenzar.',
    }
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const sendMessage = async () => {
    if (!input.trim() || loading) return

    const userMsg = { role: 'user', text: input }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setLoading(true)

    try {
      const res = await axios.post('http://127.0.0.1:8000/api/chat', {
        query: input
      })
      setMessages(prev => [...prev, { role: 'agent', text: res.data.response }])
    } catch (err) {
      setMessages(prev => [...prev, {
        role: 'agent',
        text: '> ERROR: No se pudo conectar con el servidor.'
      }])
    } finally {
      setLoading(false)
    }
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  return (
    <div className="chat-container">
      {/* Header */}
      <div className="chat-header" style={PIXEL_BORDER}>
        <span className="blink">▶</span> CYBER_AGENT // SECURITY TERMINAL
        <span className="header-status">[ ONLINE ]</span>
      </div>

      {/* Messages */}
      <div className="chat-messages">
        {messages.map((msg, i) => (
          <div key={i} className={`message ${msg.role}`}>
            <span className="message-prefix">
              {msg.role === 'user' ? '> USER:' : '> AGENT:'}
            </span>
            <pre className="message-text">{msg.text}</pre>
          </div>
        ))}

        {loading && (
          <div className="message agent">
            <span className="message-prefix">&gt; AGENT:</span>
            <pre className="message-text blink">Analizando...</pre>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="chat-input-area" style={PIXEL_BORDER}>
        <span className="input-prefix">&gt;_</span>
        <textarea
          className="chat-input"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Escribe tu consulta de seguridad..."
          rows={2}
          disabled={loading}
        />
        <button
          className="send-btn"
          onClick={sendMessage}
          disabled={loading}
          style={PIXEL_BORDER}
        >
          SEND
        </button>
      </div>
    </div>
  )
}