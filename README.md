# Benchmarking-Cryptographic-alogorithms-on-ESP8266-Arduino
Benchmarking Cryptographic alogorithms on ESP8266 Arduino- AES-128,192,256,  CHACHA, CHACHA Poly, Speck, Speck Tiny, Etc.....
#About our work:
 In this project, the focus is to provide an experimental benchmark study that shows the cost (e.g., processing time of encryption and decryption algorithms) of applying different security protocols on restricted devices equipped with lightweight Arduino ESP8266 sensor platform.
 <h5>The library is split into two main sections: Core and light-weight.</h5>
        <h2>
            <a class="anchor" id="crypto_core_algorithms"></a>
            Core algorithms
        </h2>

        <ul>
            <li>Authenticated encryption with associated data (AEAD): ChaChaPoly
            <li>Block ciphers: <a title="AES block cipher with 128-bit keys. ">AES128</a>, <a title="AES block cipher with 192-bit keys. ">AES192</a>, <a title="AES block cipher with 256-bit keys.">AES256</a> </li>
            <li>Stream ciphers: <a title="ChaCha stream cipher. ">ChaCha</a> </li>
            <li>Message authenticators: <a title="Poly1305 message authenticator. ">Poly1305</a></li>
            <li>Random number generation: <a class="el" href="classRNGClass.html">RNG</a></li>
        </ul>
        <h2>
            <a class="anchor" id="crpto_lw_algorithms"></a>
            Light-weight algorithms
        </h2>
        <ul>
            <li>Authenticated encryption with associated data (AEAD): <a class="el" href="classAcorn128.html" title="ACORN-128 authenticated cipher. ">Acorn128</a>, <a class="el" href="classAscon128.html" title="ASCON-128 authenticated cipher. ">Ascon128</a> </li>
            <li>Block ciphers: <a class="el" href="classSpeck.html" title="Speck block cipher with a 128-bit block size. ">Speck</a>, <a class="el" href="classSpeckSmall.html" title="Speck block cipher with a 128-bit block size (small-memory version). ">SpeckSmall</a>, <a class="el" href="classSpeckTiny.html" title="Speck block cipher with a 128-bit block size (tiny-memory version). ">SpeckTiny</a></li>
        </ul>
