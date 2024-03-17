package com.app.tddt4iots.controller;

import com.app.tddt4iots.entities.EnergyQuality;
import com.app.tddt4iots.repository.EnergyQualityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/energyquality")
public class EnergyQualityController {

    @Autowired
    private EnergyQualityRepository energyqualityRepository;

    @GetMapping
    public ResponseEntity<List<EnergyQuality>> getEnergyQuality() {
        List<EnergyQuality> listEnergyQuality = energyqualityRepository.findAll();
        return ResponseEntity.ok(listEnergyQuality);
    }

    @PostMapping
    public ResponseEntity<EnergyQuality> insertEnergyQuality(@RequestBody EnergyQuality energyquality) {
        EnergyQuality newEnergyQuality = energyqualityRepository.save(energyquality);
        return ResponseEntity.ok(newEnergyQuality);
    }

    @PutMapping
    public ResponseEntity<EnergyQuality> updateEnergyQuality(@RequestBody EnergyQuality energyquality) {
        EnergyQuality upEnergyQuality = energyqualityRepository.save(energyquality);
        if (upEnergyQuality != null) {
            return ResponseEntity.ok(upEnergyQuality);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping(value = "{id}")
    public ResponseEntity<EnergyQuality> deletePersons(@PathVariable("id") Long EnergyLevels) {
        energyqualityRepository.deleteById(EnergyLevels);
        return ResponseEntity.ok(null);
    }

}
