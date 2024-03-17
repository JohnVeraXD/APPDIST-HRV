package com.app.tddt4iots.controller;

import com.app.tddt4iots.entities.EnergyRateSettings;
import com.app.tddt4iots.repository.EnergyRateSettingsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/energyratesettings")
public class EnergyRateSettingsController {

    @Autowired
    private EnergyRateSettingsRepository energyratesettingsRepository;

    @GetMapping
    public ResponseEntity<List<EnergyRateSettings>> getEnergyRateSettings() {
        List<EnergyRateSettings> listEnergyRateSettings = energyratesettingsRepository.findAll();
        return ResponseEntity.ok(listEnergyRateSettings);
    }

    @PostMapping
    public ResponseEntity<EnergyRateSettings> insertEnergyRateSettings(@RequestBody EnergyRateSettings energyratesettings) {
        EnergyRateSettings newEnergyRateSettings = energyratesettingsRepository.save(energyratesettings);
        return ResponseEntity.ok(newEnergyRateSettings);
    }

    @PutMapping
    public ResponseEntity<EnergyRateSettings> updateEnergyRateSettings(@RequestBody EnergyRateSettings energyratesettings) {
        EnergyRateSettings upEnergyRateSettings = energyratesettingsRepository.save(energyratesettings);
        if (upEnergyRateSettings != null) {
            return ResponseEntity.ok(upEnergyRateSettings);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping(value = "{id}")
    public ResponseEntity<EnergyRateSettings> deletePersons(@PathVariable("id") Long id) {
        energyratesettingsRepository.deleteById(id);
        return ResponseEntity.ok(null);
    }

}
