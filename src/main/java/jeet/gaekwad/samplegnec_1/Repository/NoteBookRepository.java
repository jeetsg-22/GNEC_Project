package jeet.gaekwad.samplegnec_1.Repository;

import jeet.gaekwad.samplegnec_1.DTOs.AudioFileDTO;
import jeet.gaekwad.samplegnec_1.Model.AudioFile;
import jeet.gaekwad.samplegnec_1.Model.NoteBook;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface NoteBookRepository extends JpaRepository<NoteBook, Long> {
    List<NoteBook> findByCreatedBy_AccountId(Long accountId);
}
