package dev.serverhands.protocol

import dev.serverhands.crypto.Codec
import dev.serverhands.crypto.ProtocolException
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509ExtendedTrustManager

/** What the pairing QR carries, and what the app stores afterwards: the only trust root for a server. */
class Pin(val host: String, val port: Int, val spkiSha256: ByteArray, val serverPub: ByteArray) {
    /** First 16 hex chars of SHA-256(server key), grouped; shown to the user. */
    val fingerprint: String
        get() = Codec.sha256(serverPub).take(8).joinToString("") { "%02x".format(it) }.chunked(4).joinToString(" ")
}

class PairingUri(val pin: Pin, val token: ByteArray) {
    companion object {
        /** `hands://pair?v=1&host=..&port=..&spki=..&sid=..&tok=..`. Only ever called on scanned/pasted text. */
        fun parse(text: String): PairingUri {
            val t = text.trim()
            if (!t.startsWith("hands://pair?")) throw ProtocolException()
            val q = t.removePrefix("hands://pair?").split('&').mapNotNull {
                val i = it.indexOf('='); if (i < 0) null else it.substring(0, i) to it.substring(i + 1)
            }.toMap()
            fun get(k: String) = q[k] ?: throw ProtocolException()
            if (get("v") != "1") throw ProtocolException()
            val host = get("host")
            if (host.isEmpty() || host.any { it.isWhitespace() || it == '/' || it == '@' }) throw ProtocolException()
            val port = get("port").toIntOrNull()?.takeIf { it in 1..65535 } ?: throw ProtocolException()
            val spki = Codec.b64d(get("spki"))
            val sid = Codec.b64d(get("sid"))
            val tok = Codec.b64d(get("tok"))
            if (spki.size != 32 || sid.size != 32 || tok.size != 32) throw ProtocolException()
            return PairingUri(Pin(host, port, spki, sid), tok)
        }
    }
}

/** Accepts exactly one certificate: the one whose SubjectPublicKeyInfo hashes to the pin. No CA store, no hostname. */
internal class PinnedTrustManager(private val spkiSha256: ByteArray) : X509ExtendedTrustManager() {
    private fun check(chain: Array<X509Certificate>?) {
        val leaf = chain?.firstOrNull() ?: throw CertificateException("no certificate")
        if (!Codec.constantTimeEquals(Codec.sha256(leaf.publicKey.encoded), spkiSha256)) throw CertificateException("pin mismatch")
    }
    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) = check(chain)
    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?, socket: Socket?) = check(chain)
    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?, engine: SSLEngine?) = check(chain)
    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) = throw CertificateException()
    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?, socket: Socket?) = throw CertificateException()
    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?, engine: SSLEngine?) = throw CertificateException()
    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}

/** Forces TLS 1.3 on every socket the pinned context creates. */
private class Tls13Only(private val d: SSLSocketFactory) : SSLSocketFactory() {
    private fun <T : Socket> T.tls13(): T { (this as SSLSocket).enabledProtocols = arrayOf("TLSv1.3"); return this }
    override fun getDefaultCipherSuites(): Array<String> = d.defaultCipherSuites
    override fun getSupportedCipherSuites(): Array<String> = d.supportedCipherSuites
    override fun createSocket(s: Socket?, h: String?, p: Int, a: Boolean) = d.createSocket(s, h, p, a).tls13()
    override fun createSocket(h: String?, p: Int) = d.createSocket(h, p).tls13()
    override fun createSocket(h: String?, p: Int, la: java.net.InetAddress?, lp: Int) = d.createSocket(h, p, la, lp).tls13()
    override fun createSocket(a: java.net.InetAddress?, p: Int) = d.createSocket(a, p).tls13()
    override fun createSocket(a: java.net.InetAddress?, p: Int, la: java.net.InetAddress?, lp: Int) = d.createSocket(a, p, la, lp).tls13()
}

internal fun pinnedConnection(pin: Pin, path: String): HttpsURLConnection {
    val ctx = SSLContext.getInstance("TLSv1.3")
    ctx.init(null, arrayOf(PinnedTrustManager(pin.spkiSha256)), SecureRandom())
    val url = java.net.URI("https", null, pin.host, pin.port, path, null, null).toURL()
    val c = url.openConnection(java.net.Proxy.NO_PROXY) as HttpsURLConnection
    c.sslSocketFactory = Tls13Only(ctx.socketFactory)
    c.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true } // the pin replaces name checks
    return c
}
