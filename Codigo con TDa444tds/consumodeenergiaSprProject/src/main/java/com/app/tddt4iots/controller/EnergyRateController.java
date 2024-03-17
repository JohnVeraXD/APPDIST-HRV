package com.app.tddt4iots.controller;

import com.app.tddt4iots.entities.EnergyRate;
import com.app.tddt4iots.repository.EnergyRateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/energyrate")
public class EnergyRateController {

    @Autowired
    private EnergyRateRepository energyrateRepository;

    @GetMapping
    public ResponseEntity<List<EnergyRate>> getEnergyRate() {
        List<EnergyRate> listEnergyRate = energyrateRepository.findAll();
        return ResponseEntity.ok(listEnergyRate);
    }

    @PostMapping
    public ResponseEntity<EnergyRate> insertEnergyRate(@RequestBody EnergyRate energyrate) {
        EnergyRate newEnergyRate = energyrateRepository.save(energyrate);
        return ResponseEntity.ok(newEnergyRate);
    }

    @PutMapping
    public ResponseEntity<EnergyRate> updateEnergyRate(@RequestBody EnergyRate energyrate) {
        EnergyRate upEnergyRate = energyrateRepository.save(energyrate);
        if (upEnergyRate != null) {
            return ResponseEntity.ok(upEnergyRate);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping(value = "{id}")
    public ResponseEntity<EnergyRate> deletePersons(@PathVariable("id") Long kw) {
        energyrateRepository.deleteById(kw);
        return ResponseEntity.ok(null);
    }

}
