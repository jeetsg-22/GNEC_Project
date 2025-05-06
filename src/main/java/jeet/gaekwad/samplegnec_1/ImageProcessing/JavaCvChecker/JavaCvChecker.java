package jeet.gaekwad.samplegnec_1.ImageProcessing.JavaCvChecker;

import jakarta.annotation.PostConstruct;
import org.bytedeco.opencv.opencv_core.Mat;
import org.springframework.stereotype.Service;




@Service
public class JavaCvChecker {
    @PostConstruct
    public void checkJavaCVLoaded() {
        try {
            Mat mat = new Mat();  // Create an empty matrix
            System.out.println("JavaCV (OpenCV) is working Created empty Mat: " + mat);

        } catch (Throwable e) {
            System.out.println("Failed to load JavaCV  OpenCV libraries ");
            e.printStackTrace();
        }
    }
}
