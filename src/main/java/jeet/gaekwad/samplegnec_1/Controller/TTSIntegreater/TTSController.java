package jeet.gaekwad.samplegnec_1.Controller.TTSIntegreater;

import jeet.gaekwad.samplegnec_1.DTOs.TTSRequestDTO;
import jeet.gaekwad.samplegnec_1.Service.TTSIntegrater.TTSService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
public class TTSController {

    @Autowired
    private TTSService ttsService;

    @PostMapping(value = "/generate", consumes = "application/json" , produces = "audio/wav")
    public ResponseEntity<byte[]> generateTTS(@RequestBody TTSRequestDTO text) throws IOException {
        try {
            byte[] audioBytes = ttsService.generateAndSaveAudioFile(text);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType("audio/wav"));
            headers.setContentLength(audioBytes.length);
            headers.set("Content-Disposition", "inline; filename=tts_preview.mp3");

            return new ResponseEntity<>(audioBytes, headers, HttpStatus.OK);
        }catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
