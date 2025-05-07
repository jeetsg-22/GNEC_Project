package jeet.gaekwad.samplegnec_1.Service.NoteBookService;

import jeet.gaekwad.samplegnec_1.DTOs.AudioFileDTO;
import jeet.gaekwad.samplegnec_1.DTOs.NoteBookDTO;
import jeet.gaekwad.samplegnec_1.DTOs.NoteBookDetailDTO;
import jeet.gaekwad.samplegnec_1.Exception.NoteBookInvalidException;
import jeet.gaekwad.samplegnec_1.Model.Accounts;
import jeet.gaekwad.samplegnec_1.Model.AudioFile;
import jeet.gaekwad.samplegnec_1.Model.NoteBook;
import jeet.gaekwad.samplegnec_1.Repository.NoteBookRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class NoteBookServiceImpl implements NoteBookService {
    private final NoteBookRepository notebookRepository;

    @Autowired
    public NoteBookServiceImpl(NoteBookRepository notebookRepository) {
        this.notebookRepository = notebookRepository;
    }

    @Override
    public NoteBookDetailDTO getNoteBook(Long noteBookId) {
        NoteBook notebook = notebookRepository.findById(noteBookId)
                .orElseThrow(() -> new NoteBookInvalidException("Notebook not found"));

        return convertToDetailDTO(notebook);
    }
    @Override
    public List<NoteBookDTO> listNoteBooks(Long accountId) {
        List<NoteBook> notebooks = notebookRepository.findByCreatedBy_AccountId(accountId);
        return notebooks.stream().map(this::convertToDTO).collect(Collectors.toList());
    }

    @Override
    public NoteBookDTO createNoteBook(String name, Accounts accounts) {
        NoteBook notebook = new NoteBook();
        notebook.setName(name);
        notebook.setCreatedBy(accounts);
        notebook = notebookRepository.save(notebook);
        return convertToDTO(notebook);
    }

    @Override
    public NoteBookDTO deleteNoteBook(Long id) {
        NoteBook deleteNoteBook = notebookRepository.findById(id)
                .orElseThrow(() -> new NoteBookInvalidException("Notebook not found"));

        notebookRepository.delete(deleteNoteBook);

        return convertToDTO(deleteNoteBook);

    }

    @Override
    public NoteBookDTO updateNoteBook(Long id, String name) {
        NoteBook existingNoteBook = notebookRepository.findById(id).orElseThrow(
                () -> new NoteBookInvalidException("Notebook not found"));
        existingNoteBook.setName(name);
        NoteBook updatedNoteBook = notebookRepository.save(existingNoteBook);
        return convertToDTO(updatedNoteBook);
    }

    @Override
    public List<AudioFile> getAudioFilesByNotebookId(Long notebookId) {
        NoteBook notebook = notebookRepository.findById(notebookId)
                .orElseThrow(() -> new NoteBookInvalidException("Notebook not found"));

        return notebook.getAudioFiles();
    }

    private NoteBookDTO convertToDTO(NoteBook notebook) {
        NoteBookDTO dto = new NoteBookDTO();
        dto.setId(notebook.getNotebookid());
        dto.setName(notebook.getName());
        dto.setCreatedAt(notebook.getCreatedAt());
        dto.setAudioFileCount(notebook.getAudioFiles().size());
        return dto;
    }

    private NoteBookDetailDTO convertToDetailDTO(NoteBook notebook) {
        NoteBookDetailDTO dto = new NoteBookDetailDTO();
        dto.setId(notebook.getNotebookid());
        dto.setName(notebook.getName());
        dto.setCreatedAt(notebook.getCreatedAt());
        dto.setAudioFiles(notebook.getAudioFiles().stream()
                .map(audioFile -> {
                    AudioFile audioFile1 = new AudioFile();
                    audioFile1.setFilename(audioFile.getFilename());
                    audioFile1.setFormat(audioFile.getFormat());
                    audioFile1.setUpLoadedAt(LocalDateTime.now());
                    return audioFile;
                })
                .collect(Collectors.toList()));
        return dto;
    }
}
