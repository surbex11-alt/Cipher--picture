package com.asad.cipherdecoder

import android.content.ContentValues
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.latin.TextRecognizerOptions
import java.util.Base64
import kotlin.math.log2

class MainActivity : AppCompatActivity() {
    private lateinit var imageView: ImageView
    private lateinit var inputText: EditText
    private lateinit var resultText: TextView
    private var selectedUri: Uri? = null

    private val picker = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) { selectedUri = uri; imageView.setImageURI(uri); toast("Image loaded") }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState); setContentView(R.layout.activity_main)
        imageView=findViewById(R.id.imageView); inputText=findViewById(R.id.inputText); resultText=findViewById(R.id.resultText)
        findViewById<Button>(R.id.openButton).setOnClickListener { picker.launch("image/*") }
        findViewById<Button>(R.id.ocrButton).setOnClickListener { runOcr() }
        findViewById<Button>(R.id.analyzeButton).setOnClickListener { resultText.text=CipherAnalyzer.analyze(inputText.text.toString()) }
        findViewById<Button>(R.id.saveButton).setOnClickListener { saveReport() }
    }

    private fun runOcr() {
        val uri=selectedUri ?: run { toast("Open an image first"); return }
        val image=try { InputImage.fromFilePath(this,uri) } catch(e:Exception) { toast("Image error: ${e.message}"); return }
        TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS).process(image)
            .addOnSuccessListener { inputText.setText(it.text); toast("OCR complete — correct the transcription before analysis") }
            .addOnFailureListener { toast("OCR failed: ${it.message}") }
    }

    private fun saveReport() {
        val report=resultText.text.toString(); if(report.isBlank()){toast("Analyze first");return}
        val cv=ContentValues().apply { put(MediaStore.Downloads.DISPLAY_NAME,"cipher_analysis_${System.currentTimeMillis()}.txt"); put(MediaStore.Downloads.MIME_TYPE,"text/plain"); put(MediaStore.Downloads.RELATIVE_PATH,Environment.DIRECTORY_DOWNLOADS) }
        val uri=contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI,cv) ?: run {toast("Could not create report");return}
        try { contentResolver.openOutputStream(uri)?.use { it.write(report.toByteArray()) }; toast("Saved to Downloads") } catch(e:Exception){toast("Save failed: ${e.message}")}
    }
    private fun toast(s:String)=Toast.makeText(this,s,Toast.LENGTH_LONG).show()
}

object CipherAnalyzer {
    fun analyze(original:String):String {
        val clean=original.filter { it.isLetterOrDigit() || it in "+/=_|:-" }.replace("|","")
        val s=StringBuilder("CIPHER IMAGE DECODER v2\n${"=".repeat(68)}\n\nINPUT\n$original\n\nNORMALIZED\n$clean\n\nCAESAR / ROT 0–25\n")
        for(n in 0..25)s.appendLine("ROT %02d: %s".format(n,caesar(clean,n)))
        s.appendLine("\nATBASH\n${atbash(clean)}\n\nREVERSE\n${clean.reversed()}\n\nBASE64")
        val b=decode64(clean)
        if(b==null)s.appendLine("\nComplete input is not valid Base64.") else { s.appendLine("\nValid Base64\nHEX: ${b.hex()}\nUTF-8: ${b.utf8()}\nEntropy: %.3f".format(entropy(b))); s.appendLine("\nTOP XOR CANDIDATES"); xorCandidates(b).forEach{(score,key,data)->s.appendLine("KEY 0x%02X score %.3f %s".format(key,score,data.utf8()))} }
        s.appendLine("\nBASE64 FRAGMENTS")
        Regex("[A-Za-z0-9+/=_-]{8,}").findAll(original).forEach{m->s.appendLine("${m.value} -> ${decode64(m.value)?.hex()?:("invalid")}")}
        s.appendLine("\nNOTE\nOCR can confuse O/0, I/1, U/V, S/5 and B/8. Correct the transcription before trusting a result.")
        return s.toString()
    }
    private fun caesar(s:String,n:Int)=s.map{c->when{c in 'A'..'Z'->((c.code-65+n)%26+65).toChar();c in 'a'..'z'->((c.code-97+n)%26+97).toChar();else->c}}.joinToString("")
    private fun atbash(s:String)=s.map{c->when{c in 'A'..'Z'->(90-(c.code-65)).toChar();c in 'a'..'z'->(122-(c.code-97)).toChar();else->c}}.joinToString("")
    private fun decode64(s:String)=try{Base64.getDecoder().decode(s)}catch(_:Exception){null}
    private fun ByteArray.hex()=joinToString(""){ "%02x".format(it.toInt() and 255) }
    private fun ByteArray.utf8()=try{toString(Charsets.UTF_8)}catch(_:Exception){contentToString()}
    private fun entropy(b:ByteArray):Double{if(b.isEmpty())return 0.0;val c=IntArray(256);b.forEach{c[it.toInt() and 255]++};return c.filter{it>0}.sumOf{val p=it.toDouble()/b.size;-p*log2(p)}}
    private fun score(b:ByteArray):Double=if(b.isEmpty())0.0 else b.count{val c=it.toInt() and 255;c in 32..126||c==9||c==10||c==13}.toDouble()/b.size
    private fun xorCandidates(b:ByteArray):List<Triple<Double,Int,ByteArray>>=(0..255).map{k->val d=ByteArray(b.size){i->(b[i].toInt() xor k).toByte()};Triple(score(d),k,d)}.sortedByDescending{it.first}.take(15)
}
