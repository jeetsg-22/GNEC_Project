package jeet.gaekwad.samplegnec_1.Service.TTSIntegrater;

import jeet.gaekwad.samplegnec_1.DTOs.TTSRequestDTO;

import java.io.IOException;

public interface TTSService {
    byte[] generateAndSaveAudioFile(TTSRequestDTO Text) throws IOException, InterruptedException;
}
