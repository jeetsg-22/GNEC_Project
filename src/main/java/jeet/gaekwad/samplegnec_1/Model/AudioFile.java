package jeet.gaekwad.samplegnec_1.Model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AudioFile {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String filename;
    private String format;
    private LocalDateTime upLoadedAt = LocalDateTime.now();


    @Column(columnDefinition = "BYTEA")
    private byte[] data;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "accountId")
    @JsonIgnore
    Accounts account;

    @ManyToOne
    @JoinColumn(name = "notebook_id")
    @JsonIgnore
    private NoteBook notebook;

}
