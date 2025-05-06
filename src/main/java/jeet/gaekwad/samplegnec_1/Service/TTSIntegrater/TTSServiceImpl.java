package jeet.gaekwad.samplegnec_1.Service.TTSIntegrater;

import jeet.gaekwad.samplegnec_1.DTOs.TTSRequestDTO;
import org.springframework.stereotype.Service;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.logging.Level;
import java.util.logging.Logger;

@Service
public class TTSServiceImpl implements TTSService {

    private final String mimic3URL = "http://mimic:59125/api/tts";
    private static final Logger logger = Logger.getLogger(TTSServiceImpl.class.getName());

    @Override
    public byte[] generateAndSaveAudioFile(TTSRequestDTO text) throws IOException, InterruptedException {
        String cleanedText = text.getText().replace("text", "").trim();
        String jsonInput = createJsonPayload(cleanedText);

        // Setup HTTP Connection
        URL url = new URL(mimic3URL);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonInput.getBytes(StandardCharsets.UTF_8));
        }

        if (conn.getResponseCode() != 200) {
            throw new RuntimeException("Failed to generate Audio File: HTTP error code : " + conn.getResponseCode());
        }

        byte[] wavBytes;
        try (InputStream is = conn.getInputStream()) {
            wavBytes = is.readAllBytes();
        }

        return convertWavtoMp3(wavBytes);
    }

    private String createJsonPayload(String cleanedText) {
        // Use ObjectMapper to build the JSON object to avoid manual string concatenation
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            return objectMapper.writeValueAsString(new TextPayload(cleanedText));
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Failed to create JSON payload", e);
            return "{}";  // Return an empty JSON object in case of error
        }
    }

    private byte[] convertWavtoMp3(byte[] wavBytes) throws IOException, InterruptedException {
        File tempFileWav = File.createTempFile("temp", ".wav");
        File tempFileMp3 = File.createTempFile("temp", ".mp3");

        try {
            Files.write(tempFileWav.toPath(), wavBytes);

            // Run ffmpeg command
            ProcessBuilder pb = new ProcessBuilder("ffmpeg", "-y", "-i", tempFileWav.getAbsolutePath(), tempFileMp3.getAbsolutePath());
            pb.redirectErrorStream(true);
            Process p = pb.start();

            // Capture ffmpeg output and error streams
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    logger.info(line);
                }
            }

            int exitCode = p.waitFor();
            if (exitCode != 0) {
                throw new IOException("ffmpeg failed to convert the file, exit code: " + exitCode);
            }

            return Files.readAllBytes(tempFileMp3.toPath());
        } finally {
            // Ensure temporary files are deleted after conversion
            tempFileWav.delete();
            tempFileMp3.delete();
        }
    }

    // Inner class for creating JSON payload
    private static class TextPayload {
        private String text;

        public TextPayload(String text) {
            this.text = text;
        }

        public String getText() {
            return text;
        }

        public void setText(String text) {
            this.text = text;
        }
    }
}
