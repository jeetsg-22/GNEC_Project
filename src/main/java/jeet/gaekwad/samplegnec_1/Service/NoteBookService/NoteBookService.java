package jeet.gaekwad.samplegnec_1.Service.NoteBookService;

import jeet.gaekwad.samplegnec_1.DTOs.NoteBookDTO;
import jeet.gaekwad.samplegnec_1.DTOs.NoteBookDetailDTO;
import jeet.gaekwad.samplegnec_1.Model.Accounts;
import jeet.gaekwad.samplegnec_1.Model.AudioFile;


import java.util.List;

public interface NoteBookService {
    List<NoteBookDTO> listNoteBooks(Long accountId);
    NoteBookDetailDTO getNoteBook(Long noteBookId);
    NoteBookDTO createNoteBook(String name , Accounts accounts);
    NoteBookDTO deleteNoteBook(Long id);
    NoteBookDTO updateNoteBook(Long id, String name);
    List<AudioFile> getAudioFilesByNotebookId(Long notebookId);


}
