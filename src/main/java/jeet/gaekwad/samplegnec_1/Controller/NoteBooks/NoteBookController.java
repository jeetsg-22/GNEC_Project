package jeet.gaekwad.samplegnec_1.Controller.NoteBooks;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jeet.gaekwad.samplegnec_1.DTOs.AudioFileDTO;
import jeet.gaekwad.samplegnec_1.DTOs.NoteBookDTO;
import jeet.gaekwad.samplegnec_1.DTOs.NoteBookDetailDTO;
import jeet.gaekwad.samplegnec_1.Model.Accounts;
import jeet.gaekwad.samplegnec_1.Model.AudioFile;
import jeet.gaekwad.samplegnec_1.Model.NoteBook;
import jeet.gaekwad.samplegnec_1.Repository.AccountRepository;
import jeet.gaekwad.samplegnec_1.Repository.NoteBookRepository;
import jeet.gaekwad.samplegnec_1.Service.AccountService.AccountService;
import jeet.gaekwad.samplegnec_1.Service.NoteBookService.NoteBookService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "Notebook Management APIs", description = "Endpoints for creating, viewing, and listing user notebooks.")
@RestController
@RequestMapping("/v1/notebooks")
public class NoteBookController {

    private final NoteBookService notebookService;
    private final AccountService accountService;
    private final AccountRepository accountRepository;
    private final NoteBookRepository noteBookRepository;

    @Autowired
    public NoteBookController(NoteBookService notebookService, AccountService accountService , AccountRepository accountRepository, NoteBookRepository noteBookRepository) {
        this.notebookService = notebookService;
        this.accountService = accountService;
        this.accountRepository = accountRepository;
        this.noteBookRepository = noteBookRepository;
    }

    @Operation(
            summary = "List all Notebooks for current user",
            description = "Retrieve a list of all notebooks belonging to the currently authenticated user."
    )
    @GetMapping
    public ResponseEntity<List<NoteBookDTO>> listNotebooks() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        Accounts account = accountRepository.findByUsername(username);

        List<NoteBookDTO> notebooks = notebookService.listNoteBooks(account.accountId);
        return ResponseEntity.ok(notebooks);

    }

    @Operation(
            summary = "View a specific Notebook by ID",
            description = "Retrieve detailed information of a specific notebook by providing its notebook ID."
    )
    @GetMapping("/{id}")
    public ResponseEntity<NoteBookDetailDTO> viewNotebook(@PathVariable Long id) {
        NoteBookDetailDTO notebook = notebookService.getNoteBook(id);
        return ResponseEntity.ok(notebook);
    }

    @Operation(
            summary = "Create a new Notebook",
            description = "Create a new notebook for the currently authenticated user by providing a notebook name."
    )
    @PostMapping
    public ResponseEntity<NoteBookDTO> createNotebook(@RequestParam String name) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        Accounts account = accountRepository.findByUsername(username);

        NoteBookDTO notebook = notebookService.createNoteBook(name, account);
        return ResponseEntity.ok(notebook);
    }
    @Operation(
            summary = "delete the Notebook",
            description = "Deleting the Notebook for the currently authenticated user by providing the notebook id"
    )
    @DeleteMapping("/{id}")
    public ResponseEntity<NoteBookDTO> deleteNotebook(@PathVariable("id") Long id) {
        NoteBookDTO noteBookDTO = notebookService.deleteNoteBook(id);
        return ResponseEntity.ok(noteBookDTO);
    }
    @Operation(
            summary = "update the NoteBook",
            description = "Updating the Name of notebook via Long id and the Name of Notebook "

    )
    @PutMapping()
    public ResponseEntity<NoteBookDTO> updateNotebook(@RequestParam Long id, @RequestParam String name) {
        NoteBookDTO updatedNoteBook = notebookService.updateNoteBook(id, name);
        return ResponseEntity.ok(updatedNoteBook);
    }
    @Operation(
            summary = "Get audio files from a notebook",
            description = "Returns a list of audio files for the given notebook ID."
    )
    @GetMapping("/{id}/audio-files")
    public ResponseEntity<List<AudioFile>> getAudioFilesByNotebookId(@PathVariable("id") Long id) {
        List<AudioFile> audioFiles = notebookService.getAudioFilesByNotebookId(id);
        return ResponseEntity.ok(audioFiles);
    }


}
